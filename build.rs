use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Set SONAME for versioned shared library
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let major_version = version.split('.').next().unwrap();

    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "linux" {
        println!("cargo:rustc-link-arg=-Wl,-soname,libvmod_cel.so.{}", major_version);
    }
}