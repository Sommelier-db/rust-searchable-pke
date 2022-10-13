use std::ffi::*;
use std::os::raw::c_char;

pub(crate) fn str2ptr(str: String) -> *mut c_char {
    let c_str = CString::new(str).unwrap();
    c_str.into_raw()
}

pub(crate) fn ptr2str<'a>(ptr: *mut c_char) -> &'a str {
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().unwrap()
}

pub(crate) fn drop_ptr(ptr: *mut c_char) {
    let cstring = unsafe { CString::from_raw(ptr) };
    drop(cstring);
}
