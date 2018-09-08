p5-spy: A sampling profiler for Perl programs.
=====
[![Build Status](https://travis-ci.org/rurban/p5-spy.svg?branch=master)](https://travis-ci.org/benfred/p5-spy)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/x0jwd5ygaybsa0md?svg=true)](https://ci.appveyor.com/project/rurban/p5-spy)

p5-spy is a sampling profiler for Perl programs. It lets you visualize what your Perl
program is spending time on without restarting the program or modifying the code in any way.
p5-spy is extremely low overhead: it is written in Rust for speed and doesn't run
in the same process as the profiled Perl program, nor does it interrupt the running program
in any way. This means p5-spy is safe to use against production Perl code.

p5-spy works on Linux, OSX and Windows, and supports profiling all recent versions of the
Perl and cperl interpreter (versions 5.6 - 5.28).

## Installation

Prebuilt binary wheels can be installed from CPAN with:

```
cpan App::p5-spy
```

If you're a Rust user, p5-spy can also be installed with:

```
cargo install p5-spy
```

## Usage

p5-spy works from the command line and takes either the PID of the program you want to sample from or the command line of the perl program you want to run:

``` bash
p5-spy --pid 12345
# OR
p5-spy -- perl myprogram.pl <args...>
```

The default visualization is a [top-like](https://linux.die.net/man/1/top) live view of your perl program:

![console viewer demo](./images/console_viewer.gif)

There is also support for generating [flame graphs](http://www.brendangregg.com/flamegraphs.html) from the running process:

``` bash
p5-spy --flame profile.svg --pid 12345
# OR
p5-spy --flame profile.svg -- perl myprogram.pl <args...>
```

Which will generate a SVG file looking like:

![flame graph](./images/flamegraph.svg)

It also possible to dump out the current call stack for each thread by passing ```--dump``` to the command line.

## Frequently Asked Questions

### Why do we need another Perl profiler?

This project aims to let you profile and debug any running Perl program, even if the program is
serving production traffic.

While there are many other perl profiling projects, almost all of them
require modifying the profiled program in some way. Usually, the
profiling code runs inside of the target perl process, which will slow
down and change how the program operates. This means it's not
generally safe to use these profilers for debugging issues in
production services since they will usually have a noticeable impact
on performance. The only other sampling Perl profilers that runs
totally in a separate process are Instruments and Dtrace on darwin,
and perf on linux.

### How does p5-spy work?

p5-spy works by directly reading the memory of the perl program using the
[process_vm_readv](http://man7.org/linux/man-pages/man2/process_vm_readv.2.html) system call on Linux,
the [vm_read](https://developer.apple.com/documentation/kernel/1585350-vm_read?language=objc) call on OSX
or the [ReadProcessMemory](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx) call on Windows.

Figuring out the call stack of the Perl program is done by looking at
 the global PerlInterpreter variable to get all the Perl threads
 running in the interpreter, and then iterating over each
 ?PL_FrameObject? in each thread to get the call stack. Since the Perl
 ABI changes between versions, we use
 rusts' [bindgen](https://github.com/rust-lang-nursery/rust-bindgen)
 to generate different rust structures for each Perl interperator
 class we care about and use these generated structs to figure out the
 memory layout in the Perl program.

Getting the memory address of the Perl Interpreter can be a little
tricky due to
[Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization). If the target perl interpreter ships with symbols it is pretty easy to
figure out the memory address of the interpreter by dereferencing the
```interp_head``` or ```_PyRuntime``` variables depending on the Perl
version. However, many Perl versions are shipped with either stripped
binaries or shipped without the corresponding PDB symbol files on
Windows. In these cases we scan through the BSS section for addresses
that look like they may point to a valid PerlInterpreter and check
if the layout of that address is what we expect.


### Can p5-spy profile native extensions?

Since we're getting the call stacks of the perl program by looking at
the PerlInterpreter we don't yet get information about non-perl
threads and can't profile native extensions like those written in
languages like Cython or C++. Native code will instead show up as
spending time in the line of `Perl_pp_enterxssub`/`Perl_pp_entersub` that
calls the native function, rather than as it's own entry right now.

It should be possible to use something
like [libunwind](https://www.nongnu.org/libunwind/) or binutils
libbacktrace to profile the native code in the Perl Extensions.

### When do you need to run as sudo?

p5-spy works by reading memory from a different perl process, and this
might not be allowed for security reasons depending on your OS and
system settings. In many cases, running as a root user (with sudo or
similar) gets around these security restrictions.  OSX always requires
running as root, but on Linux it depends on how you are launching
p5-spy and the system security settings.

On Linux the default configuration is to require root permissions when
attaching to a process that isn't a child.  For p5-spy this means you
can profile without root access by getting p5-spy to create the
process (```py-spy -- perl myprogram.py```) but attaching to an
existing process by specifying a PID will usually require root
(```sudo py-spy -pid 123456```).  You can remove this restriction on
linux by setting the
[ptrace_scope sysctl variable](https://wiki.ubuntu.com/SecurityTeam/Roadmap/KernelHardening#ptrace_Protection).

<!--
### Running p5-spy in Docker
TODO: talk about profiling programs in docker containers, can do from host OS etc

Running p5-spy inside of a docker container will also usually bring up a permissions denied error even when running as root.
This error is caused by docker restricting the process_vm_readv system call we are using. This can be overriden by setting
[```--cap-add SYS_PTRACE```](https://docs.docker.com/engine/security/seccomp/) when starting the docker container.
-->

### Why am I having issues profiling /usr/bin/perl on OSX?

OSX has a featured called [System Integrity Protection](https://en.wikipedia.org/wiki/System_Integrity_Protection) that prevents even the root user from reading memory from any binary located in /usr/bin. Unfortunately, this includes the perl interpreter that ships with OSX.

There are a couple of different ways to deal with this:
 * You can install a different Perl distribution (you probably want to migrate away from perl5 to cperl anyways =)
 * You can use [perlbrew](https://???/) to run the system perl in an environment where SIP doesn't apply.
 * You can [disable System Integrity Protection](https://www.macworld.co.uk/how-to/mac/how-turn-off-mac-os-x-system-integrity-protection-rootless-3638975/).

### Does this run on BSD? Support 32-bit Windows?

Not yet =).

## Credits

p5-spy is heavily inspired by [Julia Evans](https://github.com/jvns/) excellent work on [rbspy](http://github.com/rbspy/rbspy), and adjusted from [Ben Frederickson's](https://github.com/benfred/) [py-spy](http://github.com/benfred/py-spy).

In particular, the code to generate the flamegraphs is taken directly
from rbspy, and this project uses the
([read-process-memory](https://github.com/luser/read-process-memory)
and [proc-maps](https://github.com/benfred/proc-maps)) crates that
were spun off from rbspy.

## License

p5-spy is released under the GNU General Public License v3.0, see  [LICENSE](https://github.com/rurban/p5-spy/blob/master/LICENSE) file for the full text.
