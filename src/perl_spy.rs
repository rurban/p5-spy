use std;
use std::mem::size_of;
use std::slice;
use std::path::Path;

use failure::{Error, ResultExt};
use read_process_memory::{Pid, TryIntoProcessHandle, copy_address, ProcessHandle};
use proc_maps::{get_process_maps, MapRange};
use perl_versions::{cperl5_28_0d, cperl5_28_0_thr, cperl5_22_5d, perl5_26_2, perl5_10_1_nt};
                    /*cperl5_26_2_nt, perl5_26_0_thr, perl5_22_0_nt, perl5_24_0_nt, perl5_26_0_nt, perl5_28_0_nt,
                    perl5_16_0d, perl5_22_0d, perl5_26_0d, perl5_10_0d_nt, perl5_22_0d_nt,
                    perl5_24_0d_nt, perl5_26_0d_nt, perl5_28_0d_nt, cperl5_28_0_thr, cperl5_28_0_nt,
                    , cperl5_28_0d_nt*/

use perl_interpreters;
use stack_trace::{StackTrace, get_stack_traces};
use binary_parser::{parse_binary, BinaryInfo};
use utils::{copy_struct, copy_pointer};
use perl_interpreters::{InterpreterState, ThreadState};

#[derive(Debug)]
pub struct PerlSpy {
    pub pid: Pid,
    pub process: ProcessHandle,
    pub version: Version,
    pub interpreter_address: usize,
    pub threadstate_address: usize,
    pub perl_filename: String,
    pub perl_install_path: String,
    pub version_string: String
}

impl PerlSpy {
    pub fn new(pid: Pid) -> Result<PerlSpy, Error> {
        let process = pid.try_into_process_handle().context("Failed to open target process")?;

        // get basic process information (memory maps/symbols etc)
        let perl_info = PerlProcessInfo::new(pid)?;

        let version = get_perl_version(&perl_info, process)?;
        info!("perl version {} detected", version);

        let interpreter_address = get_interpreter_address(&perl_info, process, &version)?;
        info!("Found interpreter at 0x{:016x}", interpreter_address);

        // TODO lets us figure out which thread has the GIL
        let threadstate_address = match perl_info.get_symbol("_PyThreadState_Current") {
            Some(&addr) => {
                info!("Found _PyThreadState_Current @ 0x{:016x}", addr);
                addr as usize
            },
            None => {
                warn!("Failed to find _PyThreadState_Current symbol - won't be able to detect GIL usage");
                0
            }
        };

        // Figure out the base path of the perl install
        let perl_install_path = {
            let mut perl_path = Path::new(&perl_info.perl_filename);
            if let Some(parent) = perl_path.parent() {
                perl_path = parent;
                if perl_path.to_str().unwrap().ends_with("/bin") {
                    if let Some(parent) = perl_path.parent() {
                        perl_path = parent;
                    }
                }
            }
            perl_path.to_str().unwrap().to_string()
        };

        let version_string = format!("perl{}.{}", version.major, version.minor);

        Ok(PerlSpy{pid, process, version, interpreter_address, threadstate_address,
                     perl_filename: perl_info.perl_filename,
                     perl_install_path,
                     version_string})
    }

    /// Creates a PerlSpy object, retrying up to max_retries times
    /// mainly useful for the case where the process is just started and
    /// symbols/perl interpreter might not be loaded yet
    pub fn retry_new(pid: Pid, max_retries:u64) -> Result<PerlSpy, Error> {
        let mut retries = 0;
        loop {
            let err = match PerlSpy::new(pid) {
                Ok(process) => {
                    // verify that we can load a stack trace before returning success
                    match process.get_stack_traces() {
                        Ok(_) => return Ok(process),
                        Err(err) => err
                    }
                },
                Err(err) => err
            };

            // If we failed, retry a couple times before returning the last error
            retries += 1;
            if retries >= max_retries {
                return Err(err);
            }
            info!("Failed to connect to process, retrying. Error: {}", err);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Gets a StackTrace for each thread in the current process
    // different for API, multi/thread/not, DEBUGGING
    pub fn get_stack_traces(&self) -> Result<Vec<StackTrace>, Error> {
        match self.version {
            // Currently 3.7.x and 3.8.0a0 have the same ABI, but this might change
            // as 3.8 evolvess
            //Version{major: 3, minor: 8, ..} => self._get_stack_traces::<v3_7_0::_is>(),
            //Version{major: 3, minor: 7, ..} => self._get_stack_traces::<v3_7_0::_is>(),
            //Version{major: 3, minor: 6, ..} => self._get_stack_traces::<v3_6_6::_is>(),
            //// ABI for 3.4 and 3.5 is the same for our purposes
            //Version{major: 3, minor: 5, ..} => self._get_stack_traces::<v3_5_5::_is>(),
            //Version{major: 3, minor: 4, ..} => self._get_stack_traces::<v3_5_5::_is>(),
            //Version{major: 3, minor: 3, ..} => self._get_stack_traces::<v3_3_7::_is>(),
            // ABI for 2.3/2.4/2.5/2.6/2.7 is also compatible
            Version{major: 2, minor: 3...7, ..} => self._get_stack_traces::<cperl5_22_5d::interpreter>(),
            _ => Err(format_err!("Unsupported version of Perl: {}", self.version)),
        }
    }

    // implementation of get_stack_traces, where we have a type for the InterpreterState
    fn _get_stack_traces<I: InterpreterState>(&self) -> Result<Vec<StackTrace>, Error> {
        // figure out what thread has the GIL by inspecting _PyThreadState_Current
        let mut gil_thread_id = 0;
        if self.threadstate_address > 0 {
            let addr: usize = copy_struct(self.threadstate_address, &self.process)?;
            if addr != 0 {
                let threadstate: I::ThreadState = copy_struct(addr, &self.process)?;
                gil_thread_id = threadstate.thread_id();
            }
        }

        // Get the stack traces for each thread
        let interp: I = copy_struct(self.interpreter_address, &self.process)
            .context("Failed to copy PyInterpreterState from process")?;
        let mut traces = get_stack_traces(&interp, &self.process)?;

        // annotate traces to indicate which thread is holding the gil (if any),
        // and to provide a shortened filename
        for trace in &mut traces {
            if trace.thread_id == gil_thread_id {
                trace.owns_gil = true;
            }
            for frame in &mut trace.frames {
                frame.short_filename = Some(self.shorten_filename(&frame.filename).to_owned());
            }
        }
        Ok(traces)
    }

    /// We want to display filenames without the boilerplate of the perl installation
    /// directory etc. This strips off common prefixes from perl library code.
    pub fn shorten_filename<'a>(&self, filename: &'a str) -> &'a str {
        if filename.starts_with(&self.perl_install_path) {
            let mut filename = &filename[self.perl_install_path.len() + 1..];
            if filename.starts_with("lib") {
                filename = &filename[4..];
                if filename.starts_with(&self.version_string) {
                    filename = &filename[self.version_string.len() + 1..];
                }
                if filename.starts_with("site-packages") {
                    filename = &filename[14..];
                }
            }
            filename
        } else {
            filename
        }
    }
}
/// Returns the version of perl running in the process.
fn get_perl_version(perl_info: &PerlProcessInfo, process: ProcessHandle)
        -> Result<Version, Error> {
    // If possible, grab the sys.version string from the processes memory (mac osx).
    if let Some(&addr) = perl_info.get_symbol("PL_version") {
        info!("Getting version from symbol address");
        return Ok(Version::scan_bytes(&copy_address(addr as usize, 128, &process)?)?);
    }

    // otherwise get version info from scanning BSS section for sys.version string
    info!("Getting version from perl binary BSS");
    let bss = copy_address(perl_info.perl_binary.bss_addr as usize,
                           perl_info.perl_binary.bss_size as usize, &process)?;
    match Version::scan_bytes(&bss) {
        Ok(version) => return Ok(version),
        Err(err) => {
            info!("Failed to get version from BSS section: {}", err);
            // try again if there is a libperl.so
            if let Some(ref libperl) = perl_info.libperl_binary {
                info!("Getting version from libperl BSS");
                let bss = copy_address(libperl.bss_addr as usize,
                                       libperl.bss_size as usize, &process)?;
                match Version::scan_bytes(&bss) {
                    Ok(version) => return Ok(version),
                    Err(err) => info!("Failed to get version from libperl BSS section: {}", err)
                }
            }
        }
    }

    // the perl_filename might have the version encoded in it (/usr/bin/perl5.28.0 etc).
    // try reading that in (will miss patch level on perl, but that shouldn't matter)
    info!("Trying to get version from path: {}", perl_info.perl_filename);
    let path = std::path::Path::new(&perl_info.perl_filename);
    if let Some(perl) = path.file_name() {
        if let Some(perl) = perl.to_str() {
            if perl.starts_with("perl") {
                let tokens: Vec<&str> = perl[6..].split('.').collect();
                if tokens.len() >= 2 {
                    if let (Ok(major), Ok(minor)) = (tokens[0].parse::<u64>(), tokens[1].parse::<u64>()) {
                        return Ok(Version{major, minor, patch:0, release_flags: "".to_owned()})
                    }
                }
            }
        }
    }
    Err(format_err!("Failed to find perl version from target process"))
}

fn get_interpreter_address(perl_info: &PerlProcessInfo,
                           process: ProcessHandle,
                           version: &Version) -> Result<usize, Error> {
    // get the address of the main PyInterpreterState object from loaded symbols if we can
    // (this tends to be faster than scanning through the bss section)
    match version {
        Version{major: 3, minor: 7, ..} => {
            if let Some(&addr) = perl_info.get_symbol("_PyRuntime") {
                // TODO: we actually want _PyRuntime.interpeters.head, and probably should
                // generate bindings for the pyruntime object rather than hardcode the offset (24) here
                return Ok(copy_struct((addr + 24) as usize, &process)?);
            }
        },
        _ => {
            if let Some(&addr) = perl_info.get_symbol("interp_head") {
                return Ok(copy_struct(addr as usize, &process)
                    .context("Failed to copy PyInterpreterState location from process")?);
            }
        }
    };
    info!("Failed to get interp_head from symbols, scanning BSS section from main binary");

    // try scanning the BSS section of the binary for things that might be the interpreterstate
    match get_interpreter_address_from_binary(&perl_info.perl_binary, &perl_info.maps, process, version) {
        Ok(addr) => Ok(addr),
        // Before giving up, try again if there is a libperl.so
        Err(err) => {
            info!("Failed to get interpreter from binary BSS, scanning libperl BSS");
            match perl_info.libperl_binary {
                Some(ref libperl) => {
                    Ok(get_interpreter_address_from_binary(libperl, &perl_info.maps, process, version)?)
                },
                None => Err(err)
            }
        }
    }
}

fn get_interpreter_address_from_binary(binary: &BinaryInfo,
                                       maps: &[MapRange],
                                       process: ProcessHandle,
                                       version: &Version) -> Result<usize, Error> {
    // different versions have different layouts, check as appropiate
    match version {
        //Version{major: 3, minor: 8, ..} => check_addresses::<v3_7_0::_is>(binary, maps, process),
        //Version{major: 3, minor: 7, ..} => check_addresses::<v3_7_0::_is>(binary, maps, process),
        //Version{major: 3, minor: 6, ..} => check_addresses::<v3_6_6::_is>(binary, maps, process),
        //Version{major: 3, minor: 5, ..} => check_addresses::<v3_5_5::_is>(binary, maps, process),
        //Version{major: 3, minor: 4, ..} => check_addresses::<v3_5_5::_is>(binary, maps, process),
        //Version{major: 3, minor: 3, ..} => check_addresses::<v3_3_7::_is>(binary, maps, process),
        Version{major: 28, minor: 0...1, ..} => check_addresses::<cperl5_28_0d::interpreter>(binary, maps, process),
        Version{major: 26, minor: 0...3, ..} => check_addresses::<perl5_26_2::interpreter>(binary, maps, process),
        Version{major: 22, minor: 0...5, ..} => check_addresses::<cperl5_22_5d::interpreter>(binary, maps, process),
        _ => Err(format_err!("Unsupported version of Perl: {}", version))
    }
}

// Checks whether a block of memory (from BSS/.data etc) contains pointers that are pointing
// to a valid PyInterpreterState
fn check_addresses<I>(binary: &BinaryInfo,
                      maps: &[MapRange],
                      process: ProcessHandle) -> Result<usize, Error>
        where I: perl_interpreters::InterpreterState {
    // On windows, we can't just check if a pointer is valid by looking to see if it points
    // to something in the virtual memory map. Brute-force it instead
    #[cfg(windows)]
    fn maps_contain_addr(_: usize, _: &[MapRange]) -> bool { true }

    #[cfg(not(windows))]
    use proc_maps::maps_contain_addr;

    // We're going to scan the BSS/data section for things, and try to narrowly scan things that
    // look like pointers to PyinterpreterState
    let bss = copy_address(binary.bss_addr as usize, binary.bss_size as usize, &process)?;

    #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
    let addrs = unsafe { slice::from_raw_parts(bss.as_ptr() as *const usize, bss.len() / size_of::<usize>()) };

    for &addr in addrs {
        if maps_contain_addr(addr, maps) {
            // this address points to valid memory. try loading it up as a PyInterpreterState
            // to further check
            let interp: I = match copy_struct(addr, &process) {
                Ok(interp) => interp,
                Err(_) => continue
            };

            // get the pythreadstate pointer from the interpreter object, and if it is also
            // a valid pointer then load it up.
            let threads = interp.head();
            if maps_contain_addr(threads as usize, maps) {
                // If the threadstate points back to the interpreter like we expect, then
                // this is almost certainly the address of the intrepreter
                let thread = match copy_pointer(threads, &process) {
                    Ok(thread) => thread,
                    Err(_) => continue
                };

                // as a final sanity check, try getting the stack_traces, and only return if this works
                if thread.interp() as usize == addr && get_stack_traces(&interp, &process).is_ok() {
                    return Ok(addr);
                }
            }
        }
    }
    Err(format_err!("Failed to find a perl interpreter in the .data section"))
}

/// Holds information about the perl process: memory map layout, parsed binary info
/// for perl /libperl etc.
pub struct PerlProcessInfo {
    perl_binary: BinaryInfo,
    // if perl was compiled with './Configure -Dusedl', code/symbols will
    // be in a libperl.so file instead of the executable. support that.
    libperl_binary: Option<BinaryInfo>,
    maps: Vec<MapRange>,
    perl_filename: String,
}

impl PerlProcessInfo {
    fn new(pid: Pid) -> Result<PerlProcessInfo, Error> {
        // get virtual memory layout
        let maps = get_process_maps(pid)?;
        info!("Got virtual memory maps from pid {}:", pid);
        for map in &maps {
            info!("map: {:016x}-{:016x} {}{}{} {}", map.start(), map.start() + map.size(),
                if map.is_read() {'r'} else {'-'}, if map.is_write() {'w'} else {'-'}, if map.is_exec() {'x'} else {'-'},
                map.filename().as_ref().unwrap_or(&"".to_owned()));
        }

        // parse the main perl binary
        let (perl_binary, perl_filename) = {
            #[cfg(target_os="linux")]
            let is_perl_bin = |pathname: &str| pathname.contains("bin/perl");

            #[cfg(target_os="macos")]
            let is_perl_bin = |pathname: &str| pathname.contains("bin/perl") ||
                                               pathname.contains("Perl.app");

            #[cfg(windows)]
            let is_perl_bin = |pathname: &str| pathname.contains("\\perl") &&
                                               pathname.ends_with(".exe");

            let map = maps.iter()
                .find(|m| if let Some(pathname) = &m.filename() {
                    is_perl_bin(pathname) && m.is_exec()
                } else {
                    false
                }).ok_or_else(|| format_err!("Couldn't find perl binary"))?;

            let filename = map.filename().clone().unwrap();
            info!("Found perl binary @ {}", filename);

            // TODO: consistent types? u64 -> usize? for map.start etc
            let mut perl_binary = parse_binary(&filename, map.start() as u64)?;

            // windows symbols are stored in separate files (.pdb), load
            #[cfg(windows)]
            perl_binary.symbols.extend(get_windows_perl_symbols(pid, &filename, map.start() as u64)?);

            // For OSX, need to adjust main binary symbols by substracting _mh_execute_header
            // (which we've added to by map.start already, so undo that here)
            #[cfg(target_os = "macos")]
            {
                let offset = perl_binary.symbols["_mh_execute_header"] - map.start() as u64;
                for address in perl_binary.symbols.values_mut() {
                    *address -= offset;
                }

                if perl_binary.bss_addr != 0 {
                    perl_binary.bss_addr -= offset;
                }
            }
            (perl_binary, filename)
        };

        // likewise handle libperl for perl versions compiled with -Dusedl
        let libperl_binary = {
            #[cfg(target_os="linux")]
            let is_perl_lib = |pathname: &str| pathname.contains("lib/libperl") ||
                                               pathname.contains("lib64/libperl");

            #[cfg(target_os="macos")]
            let is_perl_lib = |pathname: &str|
                pathname.contains("lib/libperl") || is_perl_framework(pathname);

            #[cfg(windows)]
            let is_perl_lib = |pathname: &str| {
                use regex::Regex;
                lazy_static! {
                    static ref RE: Regex = Regex::new(r"\\perl\d\d.dll$").unwrap();
                }
                RE.is_match(pathname)
            };

            let libmap = maps.iter()
                .find(|m| if let Some(ref pathname) = &m.filename() {
                    is_perl_lib(pathname) && m.is_exec()
                } else {
                    false
                });

            let mut libperl_binary: Option<BinaryInfo> = None;
            if let Some(libperl) = libmap {
                if let Some(filename) = &libperl.filename() {
                    info!("Found libperl binary @ {}", filename);
                    let mut parsed = parse_binary(filename, libperl.start() as u64)?;
                    #[cfg(windows)]
                    parsed.symbols.extend(get_windows_perl_symbols(pid, filename, libperl.start() as u64)?);
                    libperl_binary = Some(parsed);
                }
            }

            // On OSX, it's possible that the Perl library is a dylib loaded up from the system
            // framework (like /System/Library/Frameworks/Perl.framework/Versions/2.7/Perl)
            // In this case read in the dyld_info information and figure out the filename from there
            #[cfg(target_os = "macos")]
            {
                if libperl_binary.is_none() {
                    use proc_maps::mac_maps::get_dyld_info;
                    let dyld_infos = get_dyld_info(pid)?;

                    for dyld in &dyld_infos {
                        let segname = unsafe { std::ffi::CStr::from_ptr(dyld.segment.segname.as_ptr()) };
                        info!("dyld: {:016x}-{:016x} {:10} {}",
                            dyld.segment.vmaddr, dyld.segment.vmaddr + dyld.segment.vmsize,
                            segname.to_string_lossy(), dyld.filename);
                    }

                    let perl_dyld_data = dyld_infos.iter()
                        .find(|m| is_perl_framework(&m.filename) &&
                                  m.segment.segname[0..7] == [95, 95, 68, 65, 84, 65, 0]);

                    if let Some(libperl) = perl_dyld_data {
                        info!("Found libperl binary from dyld @ {}", libperl.filename);
                        let mut binary = parse_binary(&libperl.filename, libperl.segment.vmaddr)?;

                        // TODO: bss addr offsets returned from parsing binary are wrong
                        // (assumes data section isn't split from text section like done here).
                        // BSS occurs somewhere in the data section, just scan that
                        // (could later tighten this up to look at segment sections too)
                        binary.bss_addr = libperl.segment.vmaddr;
                        binary.bss_size = libperl.segment.vmsize;
                        libperl_binary = Some(binary);
                    }
                }
            }

            libperl_binary
        };

        Ok(PerlProcessInfo{perl_binary, libperl_binary, maps, perl_filename})
    }

    pub fn get_symbol(&self, symbol: &str) -> Option<&u64> {
        if let Some(addr) = self.perl_binary.symbols.get(symbol) {
            return Some(addr);
        }

        match self.libperl_binary {
            Some(ref binary) => binary.symbols.get(symbol),
            None => None
        }
    }
}

// We can't use goblin to parse external symbol files (like in a separate .pdb file) on windows,
// So use the win32 api to load up the couple of symbols we need on windows. Note:
// we still can get export's from the PE file
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
pub fn get_windows_perl_symbols(pid: Pid, filename: &str, offset: u64) -> std::io::Result<HashMap<String, u64>> {
    use proc_maps::win_maps::SymbolLoader;

    let handler = SymbolLoader::new(pid)?;
    let _module = handler.load_module(filename)?; // need to keep this module in scope

    let mut ret = HashMap::new();

    // currently we only need a subset of symbols, and enumerating the symbols is
    // expensive (via SymEnumSymbolsW), so rather than load up all symbols like we
    // do for goblin, just load the the couple we need directly.
    for symbol in ["_PyThreadState_Current", "interp_head", "_PyRuntime"].iter() {
        if let Ok((base, addr)) = handler.address_from_name(symbol) {
            // If we have a module base (ie from PDB), need to adjust by the offset
            // otherwise seems like we can take address directly
            let addr = if base == 0 { addr } else { offset + addr - base };
            ret.insert(String::from(*symbol), addr);
        }
    }

    Ok(ret)
}

#[cfg(target_os="macos")]
pub fn is_perl_framework(pathname: &str) -> bool {
    pathname.ends_with("/Perl") &&
    pathname.contains("/Frameworks/Perl.framework") &&
    !pathname.contains("Perl.app")
}

#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub release_flags: String
}

impl Version {
    pub fn scan_bytes(data: &[u8]) -> Result<Version, Error> {
        use regex::bytes::Regex;
        lazy_static! {
            static ref RE: Regex = Regex::new(r"5\.((1|2|3)?(0|2|4|6|8)\.(\d{1,2}))((a|b|c|rc)\d{1,2})? (.{1,64})").unwrap();
        }

        if let Some(cap) = RE.captures_iter(data).next() {
            let release = match cap.get(5) {
                Some(x) => { std::str::from_utf8(x.as_bytes())? },
                None => ""
            };
            let major = std::str::from_utf8(&cap[2])?.parse::<u64>()?;
            let minor = std::str::from_utf8(&cap[3])?.parse::<u64>()?;
            let patch = std::str::from_utf8(&cap[4])?.parse::<u64>()?;
            info!("Found matching version string '{}'", std::str::from_utf8(&cap[0])?);
            return Ok(Version{major, minor, patch, release_flags:release.to_owned()});
        }
        Err(format_err!("failed to find version string"))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}{}", self.major, self.minor, self.patch, self.release_flags)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_version() {
        let version = Version::scan_bytes(b"2.7.10 (default, Oct  6 2017, 22:29:07)").unwrap();
        assert_eq!(version, Version{major: 2, minor: 7, patch: 10, release_flags: "".to_owned()});

        let version = Version::scan_bytes(b"3.6.3 |Anaconda custom (64-bit)| (default, Oct  6 2017, 12:04:38)").unwrap();
        assert_eq!(version, Version{major: 3, minor: 6, patch: 3, release_flags: "".to_owned()});

        let version = Version::scan_bytes(b"Perl 3.7.0rc1 (v3.7.0rc1:dfad352267, Jul 20 2018, 13:27:54)").unwrap();
        assert_eq!(version, Version{major: 3, minor: 7, patch: 0, release_flags: "rc1".to_owned()});

        let version = Version::scan_bytes(b"1.7.0rc1 (v1.7.0rc1:dfad352267, Jul 20 2018, 13:27:54)");
        assert!(version.is_err(), "don't match unsupported ");

        let version = Version::scan_bytes(b"3.7 10 ");
        assert!(version.is_err(), "needs dotted version");

        let version = Version::scan_bytes(b"3.7.10fooboo ");
        assert!(version.is_err(), "limit suffixes");
    }
}
