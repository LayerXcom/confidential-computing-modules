#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

use once_cell::sync::Lazy;
mod ecalls;

use anonify_enclave::context::AnonifyEnclaveContext;
use std::backtrace;

const ANONIFY_MRENCLAVE_VERSION: usize = 0;

pub static ENCLAVE_CONTEXT: Lazy<AnonifyEnclaveContext> = Lazy::new(|| {
    backtrace::enable_backtrace(
        &*anonify_config::ENCLAVE_SIGNED_SO,
        backtrace::PrintFormat::Short,
    )
    .unwrap();
    AnonifyEnclaveContext::new(ANONIFY_MRENCLAVE_VERSION)
        .expect("Failed to instantiate ENCLAVE_CONTEXT")
});
