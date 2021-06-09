#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

mod ecalls;
mod state_transition;

use anonify_enclave::{context::AnonifyEnclaveContext, use_case::ContextWithCmdCipherPaddingSize};
use frame_sodium::rng::SgxRng;
use lazy_static::lazy_static;
use log::debug;
use std::backtrace;

const ANONIFY_MRENCLAVE_VERSION: usize = 0;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: AnonifyEnclaveContext = {
        env_logger::init();
        debug!("State Runtime Enclave initializing");

        backtrace::enable_backtrace(
            &*frame_config::ENCLAVE_SIGNED_SO,
            backtrace::PrintFormat::Short,
        )
        .unwrap();
        let mut rng = SgxRng::new().unwrap();
        AnonifyEnclaveContext::new(ANONIFY_MRENCLAVE_VERSION, &mut rng)
            .expect("Failed to instantiate ENCLAVE_CONTEXT")
    };
    pub static ref ENCLAVE_CONTEXT_WITH_CMD_CIPHER_PADDING_SIZE: ContextWithCmdCipherPaddingSize<'static> = {
        ContextWithCmdCipherPaddingSize {
            ctx: &*ENCLAVE_CONTEXT,
            cmd_cipher_padding_size: 100,
        }
    };
}
