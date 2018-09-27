/* WIP converted from Python.

This code abstracts over different perl interpreters by providing
traits for the classes/methods we need and implementations on the bindings objects
from bindgen.

Note this code is unaware of copying memory from the target process, so the
pointer addresses here refer to locations in the target process memory space.
This means we can't dereference them directly.
*/

// these bindings are automatically generated by rust bindgen
// using the scripts/bindings.sh script
use perl_versions::{cperl5_28_0d, cperl5_28_0_thr, cperl5_22_5d, perl5_26_2, perl5_10_1_nt};
                    /*cperl5_26_2_nt, perl5_26_0_thr, perl5_22_0_nt, perl5_24_0_nt, perl5_26_0_nt, perl5_28_0_nt,
                    perl5_16_0d, perl5_22_0d, perl5_26_0d, perl5_10_0d_nt, perl5_22_0d_nt,
                    perl5_24_0d_nt, perl5_26_0d_nt, perl5_28_0d_nt, cperl5_28_0_thr, cperl5_28_0_nt,
                    cperl5_28_0d, cperl5_28_0d_nt*/
use std;

pub trait InterpreterState {
    type ThreadState: ThreadState;
    fn head(&self) -> * mut Self::ThreadState;
}

pub trait ThreadState {
    type FrameObject: FrameObject;
    type InterpreterState: InterpreterState;

    fn interp(&self) -> * mut Self::InterpreterState;
    fn frame(&self) -> * mut Self::FrameObject;
    fn thread_id(&self) -> u64;
    fn next(&self) -> * mut Self;
}

pub trait FrameObject {
    type CodeObject: CodeObject;
    fn code(&self) -> * mut Self::CodeObject;
    fn lasti(&self) -> i32;
    fn back(&self) -> * mut Self;
}

pub trait CodeObject {
    type StringObject: StringObject;
    type BytesObject: BytesObject;

    fn name(&self) -> * mut Self::StringObject;
    fn filename(&self) -> * mut Self::StringObject;
    fn lnotab(&self) -> * mut Self::BytesObject;
    fn first_lineno(&self) -> i32;
}

pub trait BytesObject {
    fn size(&self) -> usize;
    fn address(&self, base: usize) -> usize;
}

pub trait StringObject {
    fn ascii(&self) -> bool;
    fn kind(&self) -> u32;
    fn size(&self) -> usize;
    fn address(&self, base: usize) -> usize;
}

fn offset_of<T, M>(object: *const T, member: *const M) -> usize {
    member as usize - object as usize
}

/// This macro provides a common impl for PyThreadState/PyFrameObject/PyCodeObject traits
/// (this code is identical across perl versions, we are only abstracting the struct layouts here).
/// String handling changes substantially between perl versions, and is handled separately.
macro_rules! PerlCommonImpl {
    ($py: ident, $bytesobject: ident, $stringobject: ident) => (
        impl InterpreterState for $py::PyInterpreterState {
            type ThreadState = $py::PyThreadState;
            fn head(&self) -> * mut Self::ThreadState { self.tstate_head }
        }

        impl ThreadState for $py::PyThreadState {
            type FrameObject = $py::PyFrameObject;
            type InterpreterState = $py::PyInterpreterState;
            fn frame(&self) -> * mut Self::FrameObject { self.frame }
            fn thread_id(&self) -> u64 { self.thread_id as u64 }
            fn next(&self) -> * mut Self { self.next }
            fn interp(&self) -> *mut Self::InterpreterState { self.interp }
        }

        impl FrameObject for $py::PyFrameObject {
            type CodeObject = $py::PyCodeObject;
            fn code(&self) -> * mut Self::CodeObject { self.f_code }
            fn lasti(&self) -> i32 { self.f_lasti }
            fn back(&self) -> * mut Self { self.f_back }
        }

        impl CodeObject for $py::PyCodeObject {
            type BytesObject = $py::$bytesobject;
            type StringObject = $py::$stringobject;
            fn name(&self) -> * mut Self::StringObject { self.co_name as * mut Self::StringObject }
            fn filename(&self) -> * mut Self::StringObject { self.co_filename as * mut Self::StringObject }
            fn lnotab(&self) -> * mut Self::BytesObject { self.co_lnotab as * mut Self::BytesObject }
            fn first_lineno(&self) -> i32 { self.co_firstlineno }
        }
    )
}

// String/Byte handling for Python 3.3+
macro_rules! Perl3StringImpl {
    ($py: ident) => (
        impl BytesObject for $py::PyBytesObject {
            fn size(&self) -> usize { self.ob_base.ob_size as usize }
            fn address(&self, base: usize) -> usize {
                base + offset_of(self, &self.ob_sval)
            }
        }

        impl StringObject for $py::PyASCIIObject {
            fn ascii(&self) -> bool { self.state.ascii() != 0 }
            fn size(&self) -> usize { self.length as usize }
            fn kind(&self) -> u32 { self.state.kind() }

            fn address(&self, base: usize) -> usize {
                if self.state.compact() == 0 {
                    // TODO: handle legacy strings. Not sure if this is needed yet
                    // for the filename/ name cases we have. This will involve
                    // adding an encoding method to this trait (and switching
                    // type to PyUnicodeObject, since we will need the extra fields)
                    panic!("legacy strings are not yet supported")
                }

                if self.state.ascii() == 1 {
                    base + std::mem::size_of::<$py::PyASCIIObject>()
                } else {
                    base + std::mem::size_of::<$py::PyCompactUnicodeObject>()
                }
            }
        }
    )
}

// String/Byte handling for Perl 2.7 (and maybe others?)
//macro_rules! Perl2StringImpl {
//    ($py: ident) => (
//        impl BytesObject for $py::PyStringObject {
//            fn size(&self) -> usize { self.ob_size as usize }
//            fn address(&self, base: usize) -> usize { base + offset_of(self, &self.ob_sval) }
//        }
//
//        impl StringObject for $py::PyStringObject {
//            fn ascii(&self) -> bool { true }
//            fn kind(&self) -> u32 { 1 }
//            fn size(&self) -> usize { self.ob_size as usize }
//            fn address(&self, base: usize) -> usize { base + offset_of(self, &self.ob_sval) }
//        }
//    )
//}
//
//// Perl 3.7
//PerlCommonImpl!(v3_7_0, PyBytesObject, PyASCIIObject);
//Perl3StringImpl!(v3_7_0);
//// Perl 3.6
//PerlCommonImpl!(v3_6_6, PyBytesObject, PyASCIIObject);
//Perl3StringImpl!(v3_6_6);
//// perl 3.5 and perl 3.4
//PerlCommonImpl!(v3_5_5, PyBytesObject, PyASCIIObject);
//Perl3StringImpl!(v3_5_5);
//// perl 3.3
//PerlCommonImpl!(v3_3_7, PyBytesObject, PyASCIIObject);
//Perl3StringImpl!(v3_3_7);
//// Perl 2.7
//PerlCommonImpl!(v2_7_15, PyStringObject, PyStringObject);
//Perl2StringImpl!(v2_7_15);
