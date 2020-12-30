#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "backup-enable")]
use anonify_enclave_backup_enabled as anonify_enclave;
#[cfg(feature = "backup-disable")]
use anonify_enclave_backup_disabled as anonify_enclave;

mod ecalls;

use anonify_enclave::context::EnclaveContext;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext = {
        let spid = std::env::var("SPID").expect("SPID is not set");
        EnclaveContext::new(spid).expect("Failed to instantiate ENCLAVE_CONTEXT")
    };
}
