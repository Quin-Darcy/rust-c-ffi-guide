use std::marker::PhantomData;

// Define a module to encapsulate the FFI binding declared with CO3.
// This isolates it from the rest of the crate and prevents namespace pollution.
mod bindings {
    use core::ffi::c_int;

    use co3::ffi;

    ffi! {
        #![unsafe(extern("C"))]

        #[symbol_name = "fill_buffer"]
        pub fn fill_buffer(#[unpack(_, c_int)] buffer: &mut [u8]) -> c_int;
    }
}

struct Buffer {
    data: Vec<u8>,

    // Phantom data to prevent auto Send/Sync traits
    _marker: PhantomData<*const ()>,
}

impl Buffer {
    fn new(size: usize) -> Self {
        Buffer {
            data: vec![0u8; size],
            _marker: PhantomData,
        }
    }

    fn fill(&mut self) -> Result<(), String> {
        // Call FFI binding
        let result =
            bindings::fill_buffer(&mut self.data);

        // Error handle
        match result {
            n if n >= 0 => Ok(()),
            _ => Err("Failed to fill buffer".to_string()),
        }
    }

    // Method for safe immutable access to buffer
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    // Method for safe mutable access to buffer
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

fn main() -> Result<(), String> {
    // Create buffer
    let size = 20;
    let mut buffer = Buffer::new(size);

    buffer.fill()?;

    println!("Buffer successfully filled with {} bytes", buffer.data.len());
    println!("First few bytes: {:?}", &buffer.as_slice()[..5]);

    // Example of mutable access
    buffer.as_mut_slice()[0] = 42;
    println!("After modification, first byte: {}", buffer.as_slice()[0]);

    Ok(())
}
