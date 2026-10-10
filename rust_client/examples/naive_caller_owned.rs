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

fn main() {
    // Allocate a buffer
    let size = 20;
    let mut buffer = vec![0u8; size];

    // Call the FFI binding
    let result =
        bindings::fill_buffer(&mut buffer);

    if result >= 0 {
        println!("Buffer successfully filled");
    } else {
        println!("Failed to fill buffer");
    }
}
