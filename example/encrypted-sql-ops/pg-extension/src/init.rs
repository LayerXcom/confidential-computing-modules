//! Initialization on extension library load.

use pgx::*;

/// Enclave ID
pub(crate) static mut EID: u64 = 0;

#[pg_guard]
pub extern "C" fn _PG_init() {
    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");
    EID = enclave.geteid();
}
