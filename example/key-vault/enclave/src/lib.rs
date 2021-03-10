#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

mod ecalls;

use key_vault_enclave::context::KeyVaultEnclaveContext;
use log::debug;
use once_cell::sync::Lazy;
use std::backtrace;

const KEY_VAULT_MRENCLAVE_VERSION: usize = 0;

pub static ENCLAVE_CONTEXT: Lazy<KeyVaultEnclaveContext> = Lazy::new(|| {
    env_logger::init();
    debug!("Key Vault Runtime Enclave initializing");

    backtrace::enable_backtrace(
        &*frame_config::ENCLAVE_SIGNED_SO,
        backtrace::PrintFormat::Short,
    )
    .unwrap();
    KeyVaultEnclaveContext::new(KEY_VAULT_MRENCLAVE_VERSION)
});
