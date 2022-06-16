use std::alloc::Layout;

#[repr(C)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
}

#[no_mangle]
pub unsafe extern "C" fn p8e_allocate(len: i32) -> *mut u8 {
    std::alloc::alloc(Layout::from_size_align_unchecked(
        len.try_into().unwrap(),
        16,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn p8e_free(ptr: *mut u8, len: i32) {
    for i in 0..len {
        // todo: is there a more efficient way to overwite this section w/ a constant value?
        std::ptr::write(ptr.offset(i.try_into().unwrap()), 0)
    }
    std::alloc::dealloc(
        ptr,
        Layout::from_size_align_unchecked(len.try_into().unwrap(), 16),
    );
}
