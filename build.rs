use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Configure symbol visibility - only export VMOD symbols
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "linux" {
        // Use linker script to control symbol visibility
        println!("cargo:rustc-link-arg=-Wl,--version-script=vmod.version");
        println!("cargo:rerun-if-changed=vmod.version");
    }

    // Set SONAME for versioned shared library
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let major_version = version.split('.').next().unwrap();

    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "linux" {
        println!("cargo:rustc-link-arg=-Wl,-soname,libvmod_cel.so.{}", major_version);
    }
}