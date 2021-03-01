#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

mod ecalls;
mod state_transition;

use anonify_enclave::context::AnonifyEnclaveContext;
use frame_sodium::rng::SgxRng;
use once_cell::sync::Lazy;
use std::backtrace;

const ANONIFY_MRENCLAVE_VERSION: usize = 0;

pub static ENCLAVE_CONTEXT: Lazy<AnonifyEnclaveContext> = Lazy::new(|| {
    backtrace::enable_backtrace(
        &*frame_config::ENCLAVE_SIGNED_SO,
        backtrace::PrintFormat::Short,
    )
    .unwrap();
    let mut rng = SgxRng::new().unwrap();
    AnonifyEnclaveContext::new(ANONIFY_MRENCLAVE_VERSION, &mut rng)
        .expect("Failed to instantiate ENCLAVE_CONTEXT")
});
