// ref: https://doc.rust-lang.org/cargo/reference/environment-variables.html
use cbindgen::Language;
use std::{env, path::PathBuf};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = target_dir()
        .join(format!("build/{}.h", package_name))
        .display()
        .to_string();

    cbindgen::Builder::new()
        .with_no_includes()
        .with_sys_include("stdbool.h")
        .with_language(Language::C)
        .include_item("EnclaveStatus")
        .include_item("UntrustedStatus")
        .include_item("EnclaveState")
        .include_item("ResultStatus")
        .include_item("RawPointer")
        .include_item("RawSig")
        .include_item("RawPubkey")
        .include_item("RawChallenge")
        .with_crate(&crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&output_file);
}

fn target_dir() -> PathBuf {
    let mut target = PathBuf::from(env::var("OUT_DIR").unwrap());
    for _ in 0..5 {
        target.pop();
    }

    target
}
