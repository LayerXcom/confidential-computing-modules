#![crate_name = "secret_backupenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod ecalls;

use key_vault_enclave::context::KeyVaultEnclaveContext;

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: KeyVaultEnclaveContext = {
        KeyVaultEnclaveContext::new()
    };
}
