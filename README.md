# Rust to C - FFI Guide

### Table of Contents
- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [Defining the C Interface](#defining-the-c-interface)
    - [The Header File](#the-header-file)
    - [The Source File](#the-source-file)
- [How FFI Works](#how-ffi-works)
    - [Symbols](#symbols)
    - [Calling Conventions](#calling-conventions)
    - [Type Matching](#type-matching)
- [Memory Management in FFI](#memory-management-in-ffi)
    - [Library-Owned Memory](#library-owned-memory)
    - [Caller-Owned Memory](#caller-owned-memory)
    - [Allocations Across the FFI Boundary](#allocations-across-the-ffi-boundary)
- [Defining the Rust Interface](#defining-the-rust-interface)
    - [Rust and C Types](#rust-and-c-types)
    - [bindgen](#bindgen)
    - [Rust FFI Binding](#the-rust-ffi-binding)
- [Calling C Functions from Rust](#calling-c-functions-from-rust)
    - [Library-Owned Memory (Naive Approach)](#library-owned-memory-naive-approach)
    - [Caller-Owned Memory (Naive Approach)](#caller-owned-memory-naive-approach)
- [Doing it All Safely](#doing-it-all-safely)
    - [Invariants](#invariants)
    - [Safe Abstractions for Library-Owned Memory](#safe-abstractions-for-library-owned-memory)
    - [Safe Abstractions for Caller-Owned Memory](#safe-abstractions-for-caller-owned-memory)
    - [Thread Safety](#thread-safety)
- [Complete Examples](#complete-examples)
    - [Library-Owned Memory Example](#library-owned-memory-example)
    - [Caller-Owned Memory Example](#caller-owned-memory-example)

### Introduction
Calling an external C function from within a Rust application requires that application to access bytes that originate outside of the application. This involves crossing several important boundaries which we will look at in detail below. Before looking at these boundaries, we will first see how to practically achieve such a function call.

### Quick Start
To get started with this project, follow these steps:

1. Clone the repository:
```bash
git clone https://github.com/Quin-Darcy/rust-c-ffi-guide
cd rust-c-ffi-guide
```
2. Build the C library:
```bash
cd c_lib
make
cd ..
```
3. **Important**: Copy the built shared library to the Cargo target directory:
```bash
# For debug builds
mkdir -p rust_client/target/debug
cp c_lib/libdemo_lib.so rust_client/target/debug/

# For release builds
mkdir -p rust_client/target/release
cp c_lib/libdemo_lib.so rust_client/target/release/
```
4. Build and run the examples:
```bash
cd rust_client

# Run the naive example
cargo run --example naive

# Run the safe example
cargo run --example safe
```

### Defining the C Interface
Throughout these notes, we will use a simple C shared library to explore how to interact with it from Rust.

#### The Header File
A header file in C typically declares the types, function prototypes, etc. that form the public interface of a module, library, or program. The shared library we will use in this ongoing example has the following header file:
```C
/* File: c_lib/include/demo_lib.h */

#ifndef DEMO_LIB_H
#define DEMO_LIB_H

// Allocate a buffer of the given size
// Returns NULL on error
char* allocate buffer(int size);

// Fill a buffer with a patern
// Returns -1 on error and return size on success
int fill_buffer(char* buffer, int size);

// Free allocated buffer
// Returns 0 on success and -1 on error
int free_buffer(char* buffer);

#endif
```

#### The Source File
Accompanying the [header file](#the-header-file) is the source file that contains the actual functions' implementations, as seen here:
```C
/* File: c_lib/src/demo_lib.c */

#include <stdlib.h>
#include "../include/demo_lib.h"

char* allocate_buffer(int size)
{
    if (size <= 0) {
        return NULL;
    }

    return (char*)malloc(size);
}

int fill_buffer(char* buffer, int size)
{
    if (buffer == NULL || size <= 0) {
        return -1;
    }

    for (int i = 0; i < size; i++) {
        buffer[i] = (char)(i % 256);
    }

    return size;
}

int free_buffer(char* buffer)
{
    if (buffer == NULL) {
        return -1;
    }

    free(buffer);
    return 0;
}
```

### How FFI Works
Now that we have seen how to practically achieve calling a C function from Rust, we will zoom in so that we can zoom back out and improve our simple first approach.

#### Symbols
A symbol in a binary file is an identifier that points to a memory address where functions, variables, or other program elements are located. In our case, and for FFI bindings in general, the symbol identifying the FFI bindings (`allocate_buffer`, `fill_buffer`, `free_buffer`) are external symbols which the Rust compiler does not generate, but rather marks as imports in the object file.

To see this, you can navigate to `rust_client/target/debug/deps` and locate the final executable. Then running [objdump](https://man7.org/linux/man-pages/man1/objdump.1.html) and grepping for `*buffer`, we see:
```bash
admin@quindarcy deps % objdump -t rust_client-2ac5215a19032364 | grep *buffer
0000000000000000         *UND* _allocate_buffer
0000000000000000         *UND* _fill_buffer
0000000000000000         *UND* _free_buffer
```
where the [`*UND*`](https://man7.org/linux/man-pages/man1/objdump.1.html) means the symbol is being referenced in the file being dumped, but is not defined there. Rather, the definition of these symbols are located in the shared C library and the linker is what resolves the undefined symbols. As mentioned in the [bindgen](#bindgen) section, the `build.rs` file handles the linking of the shared library and our Rust binary.

Another way to state what was said in the previous section, is that the `allocate_buffer`, `fill_buffer`, and `free_buffer` symbols have an *external origin*. Communicating this fact, that a symbol resides within a foreign interface is done with the `extern` keyword. It declares the existance of a symbol that's defined elsewhere.

#### Calling Conventions
Knowing where a given function or variable is defined, which is what the symbol tells you, is not enough to issue a call across the FFI boundary. A call to a foreign function also requires knowledge of the *calling convention* which reduces down to the assembly code used to invoke the function. Many things go into the calling convention including:
- How the stack frame is set up for a call
- How arguments to a function are passed (on stack vs through registers)

Since Rust has its own calling convention which is not necessarily the same one used for, say C, that is why we specify "C" in
```rust
extern "C" {
    ...
}
```
since its says to use the standard C calling convention.

#### Type Matching
As was mentioned in [Rust and C Types](#rust-and-c-types), types are not shared across the FFI boundary. A type declared in Rust is information lost upon compilation. This means the bits which make up the type must have a declaration on both sides of the boundary. The idea is to make sure that the primatives on either side of the boundary match. For example, if on the C side, an `int` is used, then the Rust equivalent is `i32` which is aliased in the crate seen earlier, `std::os::raw::c_int`.

### Memory Management with FFI
Depending on the nature of the FFI binding which is to be called, there are two scenarios related to memory management, which we will be concerned with. 

#### Library-Owned Memory
In this scenario, the library that the C function belongs to will be responsible for allocating, modifying, and freeing memory. It will then be Rust's job to make sure these actions are taken properly and safely. 

This scenario is one in which Rust is not the owner of the memory being used, it only handles it for a temporary amount of time before giving it back to the C library. 

#### Caller-Owned Memory
In this scenario, Rust will be the creator and destroyer of memory. It will lend its memory to the C function temporarily, but Rust is the owner of the  memory. 

#### Allocations Across the FFI Boundary
Memory allocated belongs to its allocator and can only be freed by the same allocator. This means memory allocated on the Rust side must be freed on the Rust side. The same is true for memory allocated on the C side. In our example code, the C shared library offers both a means for memory allocating and memory freeing.

### Defining the Rust Interface
In order for Rust to be able to call any of these functions, the Rust code must contain its own interfaces which are in some way connected to the three functions in the shared library. Such an interface is called a *foreign function interface* (FFI) binding.

An FFI binding can either be written manually or generated automatically with a tool like [bindgen](https://github.com/rust-lang/rust-bindgen). In either case, the principle remains the same: the binding is like the function prototype seen in the C header file. It must tell the Rust compiler what the function expects to be given and what the function will return.

However, as this FFI binding must be written in Rust, it is restricted to the Rust type system, which has many differences from the C type system.

#### Rust and C Types
The type systems of Rust and C differ from each other in their respective  design goals, memory layouts, etc. This seems to create an issue if we need to write a function signature in Rust for a function defined in C, which is exactly what the FFI binding is.

The Rust standard library contains definitions for each C type. This is provided through the [`std::os::raw`](https://doc.rust-lang.org/beta/std/os/raw/index.html) module. For example, in C we might have `char` and its representation in Rust would be `::std::os::raw::c_char`. This allows us to move past the issue of mapping a subset of the C type system (the types defined in the function prototype) into the Rust type system.

#### bindgen
The generation of the FFI binding, as stated earlier, can either be done manually or automatically with a tool like bindgen. The C [header file](#the-header-file) seen earlier is used by bindgen to determin what bindings it needs to generate. bindgen uses a [`build.rs`](https://rust-lang.github.io/rust-bindgen/tutorial-3.html) file which tells it where to look for to find the shared library, to link it, as well as a few other things. The result, after running `cargo build` will be a `bindings.rs` file located in an output directory chosen by [`cargo`](https://doc.rust-lang.org/stable/cargo/).

#### The Rust FFI Binding
The resulting Rust FFI binding generated by bindgen is the following:
```rust
/* File: $OUT_DIR/bindings.rs */

extern "C" {
    pub fn allocate_buffer(
        size: ::std::os::raw::c_int
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn fill_buffer(
        buffer: *mut ::std::os::raw::c_char,
        size: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn free_buffer(
        buffer: *mut ::std::os::raw::c_char
    ) -> ::std::os::raw::c_int;
}
```
These bindings are now callable from within our Rust code, provided we import them into whatever file we plan on making the calls from.

### Calling C Functions from Rust
TBD

#### Library-Owned Memory (Naive Approach)
In this section, we look at the naive way to call these bindings from the Rust project's `examples/naive.rs` file.
```rust
/* File: rust_client/examples/naive.rs */

// Define a module to encapsulate the raw FFI binding generated by bindgen.
// This isolates tit from the rest of the crate and prevents namespace pollution.
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn main() {
    // Create the buffer
    let size = 20;
    let buffer = unsafe { bindings::allocate_buffer(size) };
    if buffer.is_null() {
        panic!("Null pointer returned");
    }

    // Call the FFI binding
    match unsafe { bindings::fill_buffer(buffer, size) }
    {
        n if n >= 0 => {
            println!("Buffer successfully filled");
        },
        _ => {
            println!("Invalid arguments provided");
        }
    }

    // Free the buffer
    match unsafe { bindings::free_buffer(buffer)  }
    {
        0 => {
            println!("Buffer successfully freed");
        },
        _ => {
            println!("Failed to free buffer");
        }
    }
}
```
TODO: Enumerate the issues with this approach.

There are many issues with the above code. We will see how to write a much safer and more idiomatic version below.

#### Caller-Owned Memory (Naive Approach)
Just like the previous section, we will look at the naive approach to calling the FFI binding in the case of caller-owned memory. Here, Rust alloactes the memory and passes it to the C function for processing.
```rust
/* File: rust_client/examples/naive_caller_owned.rs */

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn main() {
    // Allocate a buffer
    let size = 20;
    let mut buffer = vec![0u8; size];

    // Get mutable pointer to the buffer's data
    let ptr = buffer.as_mut_ptr() as *mut ::std::os::raw::c_char;

    // Call the FFI binding
    let result = unsafe {
        bindings::fill_buffer(ptr, size as ::std::os::raw::c_int)
    };

    if result >= 0 {
        println!("Buffer successfully filled");
    } else {
        println!("Failed to fill buffer");
    }
}
```
TODO: Enumerate the issues with this approach.

### Doing it All Safely
There is no way around the fact that with Rust FFI bindings, the actual code which interfaces with the FFI will be unsafe since it is calling out to a function in a language which does not offer the same safety guarantees as the Rust compiler does for native Rust. The goal is then to safely encapsulate the foreign interfaces with wrappers.

#### Invariants
An *invariant* is a property that must always hold. An example of an invariant in Rust is: refernces (using `&` and `&mut`) do not dangle and always point to valid data. Ultimately, invariants represent all the assumptions required for your code to be correct. For FFI bindings, the invariants associated with the foreign code *cannot* be checked by the Rust compiler. Therefore, one of the goals of the safe wrapper around the FFI binding is to make sure that all the invariants of the wrapped code are upheld.

In the library-owned example code, the key invariants are the following:
1. **Memory Management**: The buffer allocated by `allocate_buffer` must eventually be freed by `free_buffer` exactly once to avoid memory leaks or double-free errors.
2. **Valid Pointers**: Only non-null pointers from `allocate_buffer` should be passed into `fill_buffer` and `free_buffer`.
3. **Size Consistency**: The size paranmeter passed into `fill_buffer` must match the size used when allocating the buffer with `allocate_buffer`.
4. **Lifetime Management**: The buffer must not be used after it's freed and must only be freed once.
5. **Error Handling**: Return values must be properly checked and handled.

In the caller-owned example, the key invariants are similar to those we saw in the previous case. Namely, 

1. **Memory Management**: The buffer must be properly allocated and freed exactly once.
2. **Valid Pointers**: The pointer derived from the Rust buffer must not be null.
3. **Size Consistency**: The size passed to the C funcion must match the actual buffer size.
4. **Lifetime Management**: The pointer must not be stored by the C function and used later on.
5. **Error Handling**: Return valus from C functions must be properly checked and handled.

In the subsequent sections, we will see how each of the invariants can be maintained.

#### Safe Abstractions for Library-Owned Memory
Given our example code in the library-owned case, we can create a safe abstraction to wrap our unsafe code. Namely, we can create the following struct:
```rust
/* File: rust_client/examples/safe_library_owned.rs */

struct Buffer {
    ptr: *mut ::std::os::raw::c_char,
    size: ::std::os::raw::c_int
}
```
With this wrapper, we assure the type primatives match across the FFI boundary and we hide the raw pointer as the `ptr` field is private which prevents direct access from outside the struct. Moreover, since the size information is stored along side the pointer, this ensures consistency.

Now with the `Buffer` struct defined, we can equip it with implementations that wrap the unsafe calls to the FFI bindings. We start with the constructor:
```rust
/* File: rust_client/examples/safe_library_owned.rs */

impl Buffer {
    fn new(size: usize) -> Result<Self, String> {
        // Convert usize to c_int with bounds checking
        let c_size = ::std::os::raw::c_int::try_from(size)
            .map_err(|_| "Size too large for C integer".to_string())?;

        let ptr = unsafe { bindings::allocate_buffer(c_size) };
        if ptr.is_null() {
            return Err("Failed to allocate buffer".to_string());
        }
        Ok(Buffer { ptr, size: c_size })
    }
}
```
The above implementation:
- checks for null pointers immediately after allocation;
- returns `Err` result if one is detected;
- all methods that use the pointer are implemented on the `Buffer` struct ensuring only valid pointers are used;
- the constructor is the only place where instances are created, guaranteeingt all instances have valid pointers.

This means that the **Valid Pointers** invariant is maintained as well as the **Error Handling** invariant. Also note that we send it `usize` which is more idiomatic for a Rust API.

The next implementation we need is one to wrap the call to `fill_buffer`.
```rust
/* File: rust_client/examples/safe_library_owned.rs */

impl Buffer {
    /* Same as before */

    fn fill(&mut self) -> Result<(), String> {
        let result = unsafe { bindings::fill_buffer(self.ptr, self.size) };
        match result {
            n if n>= 0 => Ok(()),
            _ => Err("Invalid arguments were provided".to_string()),
        }
    }
}
```
This implementation uses the stored size rather than requiring the caller to provide it again which eliminates the possibility of size mismatch. Thus the **Size Consistency** invariant is maintained.

The last addition we make is a destructor for the `Buffer` struct. This will function as the safe wrapper around the call to `free_buffer` and is achieved through the `Drop` trait and writing an implementation for it for `Buffer` as follows:
```rust
/* File: rust_client/examples/safe_library_owned.rs */

impl Drop for Buffer {
    fn drop(&mut self) {
        let result = unsafe { bindings::free_buffer(self.ptr) };
        if result != 0 {
            eprintln!("Warning! Failed to free buffer");
        }
    }
}
```
Implementing the `Drop` trait ensures:
- the buffer is automatically freed when the `Buffer` instance goes out of scope;
- the `free_buffer` call only happens in the `Drop` implementation which assures its only called once per allocation;
- if an error occurs or there is an early return, Rust's ownership system ensures `drop` is still called.

This means the **Memory Management** and **Lifetime Management** invariants are maintained.

#### Safe Abstractions for Caller-Owned Memory
Similar to the library-owned example, we begin by creating a safe abstraction to wrap what we need to protect
```rust
/* File: rust_client/examples/safe_caller_owned.rs */

struct Buffer {
    data: Vec<u8>,
}
```

Unlike the `Buffer` struct in the previous example, where our members had types which assured the type primatives matched across the FFI boundary, we don't need to do that explicitly here.

Instead, we use Rust's `Vec` type which has the following advantages:
- It guarantees the memory is contiguous.
- Its size can be queried directly with `.len()`.
- The `Drop` trait is automatically implemented and called when the Vec goes out of scope which frees it.

*Note: For short-lived buffers, stack allocation with arrays instead of vectors might be prefereable.*

We move on to equip this struct with methods that will assure the invariants listed earlier are upheld. We start witht the constructor:
```rust
/* File: rust_client/examples/safe_caller_owned.rs */

impl Buffer {
    fn new(size: usize) -> Self {
        Buffer {
            data: vec![0u8; size],
        }
    }
}
```

The C function `fill_buffer` is expecting a char pointer (`char *`). In C, `char` is a 1-byte type often used to represent raw bytes. In Rust, `u8` is also a 1-byte type which means the memory layouts are compatible and this informs our choise of what type to populate our Rust-side buffer with.

Additionally, we will see that in matching the memory layouts on the C and Rust sides, we can use Rust's `as_mut_ptr()` to get a raw pointer to a contiguous sequence of bytes which is precisely what the C function expects.

Moving on, we add a safe method for actually filling the buffer and calling the FFI binding.
```rust
/* File: rust_client/examples/safe_caller_owned.rs */

impl Buffer {
    /* Same as before */

    fn fill(&mut self) -> Result<(), String> {
        // Convert usize to c_int with bounds checking
        let c_size = ::std::os::raw::c_int::try_from(self.data.len())
            .map_err(|_| "Size too large for C integer".to_string())?;

        // Get mutable pointer to buffer's data
        let ptr = self.data.as_mut_ptr() as *mut ::std::os::raw::c_char;

        // Call FFI binding
        let result = unsafe {
            bindings::fill_buffer(ptr, c_size)
        };        

        // Error handle
        match result {
            n if n >= 0 => Ok(()),
            _ => Err("Failed to fill buffer".to_string()),
        }
    }
}  
```

The last methods we add are ones that allows us to safely access the buffer
```rust
/* FilE: rust_client/examples/safe_caller_owned.rs */

impl Buffer {
    /* Same as before */

    // For safe immutable access to buffer
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    // For safe mutable access to buffer
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}
```

This implementation maintains the following invariants:
1. **Memory Management**: This invariant is maintained automatically by Rusts ownership system. When the `Buffer` instance goes out of scope, Rust will automatically dop the `Vec<u8>` inside it, which frees the memory properly.
2. **Valid Pointers**: This invariant is SAtisfied because:
    - `Vec<u8>` already guarantees the pointer is never null.
    - Only one pointer is created temporarily within the `fill` method.
    - The raw pointer is never exposed outside the `fill` method.
3. **Size Consistency**: This invariant is maintained because:
    - The `self.data.len()` is used to get the exact size of the buffer.
    - Bounds checking is performed when converting to C integer type
4. **Lifetime Management**: This invarinat is maintained becuase:
    - The raw pointer only exists within the scope of `fill` method.
    - The C function cannot keep a reference to the memory beyond the function call. *Note: this is only true because we happen to know the C `fill_buffer` does not store a copy or reference to our memory. If this is not known, this implementation would not necessarily uphold this invariant.*
5. **Error Handling**: This invariant is maintained becuase:
    - We properly check the return value from the C function call.
    - We are converting between Rust and C types safely with error checking.

#### Thread Safety
There is one more invariant we must assure is maintained. That the memory pointed to by a raw C pointer has unknown sharing and thread-safety properties that Rust can't verify. That is, Rust cannot know if the C library is internally thread-safe, uses thread-local storage, if multiple threads can use the same buffer concurrently, or if the memory that the pointer refers to might be accessed or freed by other threads.

In the case of our example code, there is no guarantee that:
- The memory allocated by allocate_buffer can be safely accessed from multiple threads
- The C library doesn't keep important shared memory that could get corrupted if accessed by multiple threads at once.

In Rust, most data types automatically have the `Send` and `Sync` traits implemented for them. The `Send` trait indicates that a type can be safely transferred between threads (ownership moves across thread boundary). The `Sync` trait indicates that a type can be safely shared between threads (references simultaneously from multiple threads). Both these traits are exactly what we cannot guarantee to be true for the raw C pointer being handled.

To prevent these auto-traits, we can use the zero-sized type to mark the `Buffer` struct to behave like a type that doesn't implement these traits. This looks like this:

```rust
/* File: rust_client/examples/safe_library_owned.rs */
/* File: rust_client/examples/safe_caller_owned.rs */

use std::marker::PhantomData;

struct Buffer {
    /* Same members as before */

    // This phantom data prevents automatic Send/Sync implementation
    _marker: PhantomData<*const ()>,
}

impl Buffer {
    fn new(size: usize) -> Result<Self, String> {
        /* Everything the same */

        Ok(Buffer { ptr, size: c_size, _marker: PhantomData })
    }

    /* Everything the same */
}

/* Everything the same */
```
### Complete Examples
TBD

#### Library-Owned Memory Example
Now that we have seen how to write safe unsafe code. We look at the final `examples/safe.rs` file to see it all come together and how to call our safe wrappers from `main`:
```rust
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::marker::PhantomData;

// Define a module to encapsulate the raw FFI binding generated by bindgen.
// This isolates it from the rest of the crate and prevents namespace pollution.
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Struct to hide the raw pointer and from which we can extend
// with implementations that safely wrap the unsafe code
struct Buffer {
    ptr: *mut ::std::os::raw::c_char,
    size: ::std::os::raw::c_int,
    // Phantom data to prevent automatic Send/Sync implementation
    _marker: PhantomData<*const ()>,
}

// Safe implementations which return Result types that
// properly handles error cases
impl Buffer {
    fn new(size: usize) -> Result<Self, String> {
        // Convert usize to c_int with bounds checking
        let c_size = ::std::os::raw::c_int::try_from(size)
            .map_err(|_| "Size too large for C integer".to_string())?;

        let ptr = unsafe { bindings::allocate_buffer(c_size) };
        if ptr.is_null() {
            return Err("Failed to allocate buffer".to_string());
        }
        Ok(Buffer { ptr, size: c_size, _marker: PhantomData })
    }

    fn fill(&mut self) -> Result<(), String> {
        let result = unsafe { bindings::fill_buffer(self.ptr, self.size) };
        match result {
            n if n >=0 => Ok(()),
            _ => Err("Invalid arguments were provided".to_string()),
        }
    }
}

// This ensures the buffer is always freed
// regardless of when it goes out of scope
impl Drop for Buffer {
   fn drop(&mut self) {
        let result = unsafe { bindings::free_buffer(self.ptr) };
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
```

#### Caller-Owned Memory Example
Below if the final and full example of the safe and idiomatic way to access the FFI binding with caller-owned memory:
```rust
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::marker::PhantomData;

// Define a module to encapsulate the raw FFI binding generated by bindgen.
// This isolates it from the rest of the crate and prevents namespace pollution.
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
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
        // Convert usize to c_int with bounds check
        let c_size = ::std::os::raw::c_int::try_from(self.data.len())
            .map_err(|_| "Size too large for C integer".to_string())?;

        // Get a mutable pointer to the buffers data
        let ptr = self.data.as_mut_ptr() as *mut ::std::os::raw::c_char;

        // Call FFI binding
        let result = unsafe {
            bindings::fill_buffer(ptr, c_size)
        };

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
```
