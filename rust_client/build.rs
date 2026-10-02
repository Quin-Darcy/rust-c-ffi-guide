fn main() {
    println!("cargo:rustc-link-search=../c_lib");
    println!("cargo:rustc-link-lib=demo_lib");
    println!("cargo:rerun-if-changed=../c_lib/include/demo_lib.h");
}
