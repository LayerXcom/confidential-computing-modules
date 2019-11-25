#![crate_type = "lib"]
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use self::init_enclave::EnclaveDir;

mod init_enclave;
mod ocalls;
mod constants;
mod equote;
mod error;
mod attestation;
mod web3;
mod tests;
mod auto_ffi;

fn init_enclave() {




    let enclave = EnclaveDir::new().init_enclave().unwrap();

    println!("[+] Done!");

    enclave.destroy();
}
