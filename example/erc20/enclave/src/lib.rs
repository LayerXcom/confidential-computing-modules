#![crate_name = "erc20enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod ecalls;

use anonify_enclave::context::AnonifyEnclaveContext;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: AnonifyEnclaveContext = {
        AnonifyEnclaveContext::new().expect("Failed to instantiate ENCLAVE_CONTEXT")
    };
}
