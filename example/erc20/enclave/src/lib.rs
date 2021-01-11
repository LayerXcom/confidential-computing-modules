#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod ecalls;

use anonify_enclave::context::AnonifyEnclaveContext;
use std::backtrace;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: AnonifyEnclaveContext = {
        backtrace::enable_backtrace(
            &*anonify_config::ENCLAVE_SIGNED_SO,
            backtrace::PrintFormat::Short,
        )
        .unwrap();
        AnonifyEnclaveContext::new().expect("Failed to instantiate ENCLAVE_CONTEXT")
    };
}
