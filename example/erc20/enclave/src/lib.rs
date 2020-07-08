#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod ecalls;

use anonify_enclave::context::EnclaveContext;
use anonify_enclave::config::TEST_SPID;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext
        = EnclaveContext::new(TEST_SPID).unwrap();
}
