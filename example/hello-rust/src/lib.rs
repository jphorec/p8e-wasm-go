use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use wasm_bindgen::prelude::wasm_bindgen;

#[no_mangle]
pub extern "C" fn greet(name: *const c_char) -> *mut i8 {
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();

    let c_str = CString::new(format!("Hello, {}!", name_str)).unwrap();
    c_str.into_raw()
}

#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> i32 {
    return a + b;
}
