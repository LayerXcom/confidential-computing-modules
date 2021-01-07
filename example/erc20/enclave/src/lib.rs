#![crate_name = "anonifyenclave"]
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
        let spid = std::env::var("SPID").expect("SPID is not set");
        AnonifyEnclaveContext::new(spid).expect("Failed to instantiate ENCLAVE_CONTEXT")
    };
}
