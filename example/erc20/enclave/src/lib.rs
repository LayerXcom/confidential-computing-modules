#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

mod logics;
mod ecalls;

use anonify_enclave::context::{EnclaveContext};

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext<StateType>
        = EnclaveContext::new(TEST_SPID).unwrap();
}
