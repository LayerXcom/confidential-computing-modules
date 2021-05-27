//! Initialization on extension library load.

use frame_host::EnclaveDir;
use once_cell::sync::OnceCell;
use pgx::*;
use sgx_urts::SgxEnclave;
use std::env;

pub(crate) static ENCLAVE: OnceCell<SgxEnclave> = OnceCell::new();

#[pg_guard]
pub extern "C" fn _PG_init() {
    let is_debug: bool = env::var("IS_DEBUG")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .expect("Failed to parse IS_DEBUG");

    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");
    ENCLAVE.set(enclave).unwrap();
}
