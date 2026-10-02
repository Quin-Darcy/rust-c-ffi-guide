// Define a module to encapsulate the FFI binding declared with CO3.
// This isolates it from the rest of the crate and prevents namespace pollution.
use core::{
    ffi::{c_char, c_int},
    ptr::NonNull,
};

mod bindings {
    use super::*;

    use co3::ffi;

    ffi! {
        #![unsafe(extern("C"))]

        #[symbol_name = "allocate_buffer"]
        pub fn allocate_buffer(size: c_int) -> Option<NonNull<c_char>>;

        #[symbol_name = "free_buffer"]
        pub unsafe fn free_buffer(buffer: NonNull<c_char>) -> c_int;

        #[symbol_name = "fill_buffer"]
        pub unsafe fn fill_buffer(#[unpack(*mut c_char, c_int)] buffer: NonNull<[c_char]>) -> c_int;
    }
}

fn main() {
    // Create the buffer
    let size = 20;
    let c_size = c_int::try_from(size).expect("Size too large for C integer");
    let ptr = bindings::allocate_buffer(c_size).expect("Null pointer returned");
    let buffer = NonNull::slice_from_raw_parts(ptr, size);

    // Call the FFI binding
    match unsafe { bindings::fill_buffer(buffer) } {
        n if n >= 0 => {
            println!("Buffer successfully filled");
        },
        _ => {
            println!("Invalid arguments were provided");
        }
    }

    match unsafe { bindings::free_buffer(buffer.cast()) }
    {
        0 => {
            println!("Buffer successfully freed");
        },
        _ => {
            println!("Failed to free buffer");
        }
    }
}
