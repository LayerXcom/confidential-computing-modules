//! Initialization on extension library load.

use frame_host::EnclaveDir;
use pgx::*;
use std::env;

/// Enclave ID.
/// Mutation occurs only here.
pub(crate) static mut EID: u64 = 0;

#[pg_guard]
pub extern "C" fn _PG_init() {
    let is_debug: bool = env::var("IS_DEBUG")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .expect("Failed to parse IS_DEBUG");

    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");

    unsafe {
        EID = enclave.geteid();
    }

    log::info!(
        "Initialized encrypted-sql-ops-pg extension. Enclave ID: {}",
        unsafe { EID }
    );
}
