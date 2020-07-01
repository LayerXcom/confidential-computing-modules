use std::{env, path::PathBuf};
use bindgen::{builder, EnumVariation, RustTarget};

fn main () {
    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let rust_sgx_sdk = env::var("SGX_SDK_RUST")
        .unwrap_or_else(|_| format!("{}/sgx", dirs::home_dir().unwrap().display()));
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
        }
        _ => {
            // Treat both HW and undefined as HW
            println!("cargo:rustc-link-lib=dylib=sgx_urts");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
        }
    }

    let edl = format!("{}/edl", rust_sgx_sdk);
    let bindings = builder()
        .whitelist_recursively(false)
        .array_pointers_in_arguments(true)
        .default_enum_style(EnumVariation::Rust{ non_exhaustive: false })
        .rust_target(RustTarget::Nightly)
        .clang_arg(format!("-I{}/include", sdk_dir))
        .clang_arg(format!("-I{}", edl))
        .header("Anonify_common_u.h")
        .raw_line("#![allow(dead_code)]")
        .raw_line("use anonify_types::*;")
        .raw_line("use sgx_types::*;")
        .whitelist_function("ecall_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = target_dir();
    bindings
        .write_to_file(out_path.join("auto_ffi.rs"))
        .expect("Couldn't write bindings!");

    cc::Build::new()
        .file("Anonify_common_u.c")
        .include("/opt/sgxsdk/include")
        .include(edl)
        .compile("libAnonify_common_u.a");
}

fn target_dir() -> PathBuf {
    let mut target = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    target.push("src/bridges");
    target
}
