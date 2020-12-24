use once_cell::sync::Lazy;
use std::env;

pub const ENCLAVE_DIR: &str = ".anonify";
pub const ENCLAVE_TOKEN: &str = "enclave.token";

pub static ENCLAVE_FILE: Lazy<String> = Lazy::new(|| {
    let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("failed to get env 'ENCLAVE_PKG_NAME'");
    format!("{}.signed.so", pkg_name)
});
