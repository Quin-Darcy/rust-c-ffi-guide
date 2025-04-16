use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-search=../c_lib");
    println!("cargo:rustc-link-lib=demo_lib");
    println!("cargo:rerun-if-changed=../c_lib/include/demo_lib.h");

    let bindings = bindgen::Builder::default()
        .header("../c_lib/include/demo_lib.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    println!("Generated bindings at: {}", out_path.join("bindings.rs").display());
}
