#![crate_type = "lib"]
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use init_enclave::EnclaveDir;
use sgx_types::*;

mod init_enclave;
mod ocalls;
mod ecalls;
mod constants;
mod error;
mod web3;
mod auto_ffi;
#[cfg(test)]
mod tests;

pub fn init_enclave() -> sgx_enclave_id_t {
    let enclave = EnclaveDir::new().init_enclave().unwrap();
    enclave.geteid()
}

