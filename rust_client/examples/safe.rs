use core::{
    ffi::{c_char, c_int},
    marker::PhantomData,
    ptr::NonNull,
};

use co3::{rust_spec::RustSpec, ReprC};

// Define a module to encapsulate the FFI binding declared with CO3.
// This isolates it from the rest of the crate and prevents namespace pollution.
mod bindings {
    use super::*;

    use co3::ffi;

    ffi! {
        #![unsafe(extern("C"))]

        #[symbol_name = "allocate_buffer"]
        pub fn allocate_buffer(size: c_int) -> Option<NonNull<c_char>>;

        #[symbol_name = "free_buffer"]
        pub unsafe fn free_buffer(buffer: NonNull<c_char>) -> c_int;

        impl BufferDst {
            #[symbol_name = "fill_buffer"]
            pub unsafe fn fill(#[unpack(*mut c_char, c_int)] buffer: NonNull<Self>) -> c_int;
        }
    }
}

#[derive(RustSpec, ReprC)]
#[repr(transparent)]
#[repr_c(identity)]
struct BufferDst([c_char]);

// Struct to hide the raw pointer and from which we can extend
// with implementations that safely wrap the unsafe code
struct Buffer {
    data: NonNull<BufferDst>,
    // Phantom data to prevent automatic Send/Sync implementation
    _marker: PhantomData<*const ()>,
}

// Safe implementations which return Result types that
// properly handles error cases
impl Buffer {
    fn new(size: usize) -> Result<Self, String> {
        // Convert usize to c_int with bounds checking
        let c_size = c_int::try_from(size)
            .map_err(|_| "Size too large for C integer".to_string())?;

        let ptr = bindings::allocate_buffer(c_size)
            .ok_or("Failed to allocate buffer".to_string())?;

        let slice = NonNull::slice_from_raw_parts(ptr, c_size as usize);
        let data = NonNull::new(slice.as_ptr() as *mut BufferDst).unwrap();

        Ok(Buffer { data, _marker: PhantomData })
    }

    fn fill(&mut self) -> Result<(), String> {
        let result = unsafe { BufferDst::fill(self.data) };
        match result {
            n if n >= 0 => Ok(()),
            _ => Err("Invalid arguments were provided".to_string()),
        }
    }
}

// This ensures the buffer is always freed
// regardless of when it goes out of scope
impl Drop for Buffer {
    fn drop(&mut self) {
        let result = unsafe { bindings::free_buffer(self.data.cast()) };
        if result != 0 {
            eprintln!("Warning! Failed to free buffer");
        }
    }
}

fn main() -> Result<(), String> {
    let size = 20;
    let mut buffer = Buffer::new(size)?;

    buffer.fill()?;

    println!("Buffer successfully filled");

    Ok(())
}
