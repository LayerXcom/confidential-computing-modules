// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::{env, path::PathBuf};
use bindgen::{builder, EnumVariation, RustTarget};

fn main () {
    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let rust_sgx_sdk = env::var("SGX_SDK_RUST")
        .unwrap_or_else(|_| format!("{}/sgx", dirs::home_dir().unwrap().display()));
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rustc-link-search=native=../lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

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
        .header("Enclave_u.h")
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
}

fn target_dir() -> PathBuf {
    let mut target = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    target.push("src");
    target
}
