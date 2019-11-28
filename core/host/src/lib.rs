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
mod equote;
mod error;
mod attestation;
mod web3;
mod auto_ffi;
#[cfg(test)]
mod tests;

fn init_enclave() {

    let enclave = EnclaveDir::new().init_enclave().unwrap();
    let eid = enclave.geteid();

    println!("[+] Done!");

    enclave.destroy();
}
