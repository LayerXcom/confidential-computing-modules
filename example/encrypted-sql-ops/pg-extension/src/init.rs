//! Initialization on extension library load.

use frame_host::EnclaveDir;
use once_cell::sync::OnceCell;
use pgx::*;
use sgx_urts::SgxEnclave;
use std::env;

static ENCLAVE: OnceCell<Enclave> = OnceCell::new();

#[derive(Debug)]
pub(crate) struct Enclave(SgxEnclave);

impl Enclave {
    pub(crate) fn global() -> &'static Self {
        ENCLAVE.get().expect("enclave is not initialized")
    }

    fn init(enclave: SgxEnclave) {
        ENCLAVE.set(Self(enclave)).unwrap();
    }
}

impl Deref for Enclave {
    type Target = SgxEnclave;

    fn deref(&self) -> &SgxEnclave {
        &self.0
    }
}

#[pg_guard]
pub extern "C" fn _PG_init() {
    let is_debug: bool = env::var("IS_DEBUG")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .expect("Failed to parse IS_DEBUG");

    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");

    Enclave::init(enclave);
}
