fn main() { unsafe { let ptr: *mut i32 = std::ptr::null_mut(); *ptr = 42; } }
