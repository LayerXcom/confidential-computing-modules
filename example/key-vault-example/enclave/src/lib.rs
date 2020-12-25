#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod ecalls;

use anonify_enclave::context::EnclaveContext;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext = {
        let spid = std::env::var("SPID").expect("SPID is not set");
        let is_backup_enabled = true;
        EnclaveContext::new(spid, is_backup_enabled).expect("Failed to instantiate ENCLAVE_CONTEXT")
    };
}
