use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Run the Makefile to build the proof system for MAYO
    let status = Command::new("make").status().expect("Failed to run make");

    if !status.success() {
        panic!("Makefile execution failed");
    }
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let lib_dir = PathBuf::from(&manifest_dir).join("target/debug");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=volemayo");
    println!("cargo:rustc-env=LD_LIBRARY_PATH={}", lib_dir.display());

    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-I../vole/mayo")
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to file
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
