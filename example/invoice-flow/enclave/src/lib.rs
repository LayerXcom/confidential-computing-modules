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

use anonify_enclave::config::TEST_SPID;
use anonify_enclave::context::EnclaveContext;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext = EnclaveContext::new(TEST_SPID).unwrap();
}
