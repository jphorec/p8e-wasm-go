use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub extern fn greet(item: *const c_char) -> *const c_char {
    return unsafe { CStr::from_ptr(item).to_string_lossy().into_owned().as_ptr() as *const c_char }
}