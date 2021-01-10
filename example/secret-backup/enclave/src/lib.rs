#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod ecalls;

use key_vault_enclave::context::KeyVaultEnclaveContext;
use std::backtrace;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: KeyVaultEnclaveContext = {
        backtrace::enable_backtrace(
            &*anonify_config::ENCLAVE_SIGNED_SO,
            backtrace::PrintFormat::Short,
        )
        .unwrap();
        KeyVaultEnclaveContext::new()
    };
}
