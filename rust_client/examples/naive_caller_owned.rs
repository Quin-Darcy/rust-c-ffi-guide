/* File: examples/naive_caller_owned.rs */

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn main() {
    // Allocate a buffer
    let size = 20;
    let mut buffer = vec![0u8; size];
    
    // Get mutable pointer to the buffer's data
    let ptr = buffer.as_mut_ptr() as *mut ::std::os::raw::c_char;
    
    // Call the FFI binding to fill the buffer
    let result = unsafe { 
        bindings::fill_buffer(ptr, size as ::std::os::raw::c_int) 
    };
    
    if result >= 0 {
        println!("Buffer successfully filled");
        
        // Print the buffer contents
        println!("Buffer contents: {:?}", buffer);
    } else {
        println!("Failed to fill buffer");
    }
}
