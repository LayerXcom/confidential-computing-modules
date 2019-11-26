#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use init_enclave::EnclaveDir;

mod init_enclave;
mod ocalls;
mod constants;
mod equote;
mod error;
mod attestation;
mod web3;
mod tests;
mod auto_ffi;


fn main() {

}

fn init_enclave() {

    let enclave = EnclaveDir::new().init_enclave().unwrap();
    let eid = enclave.geteid();

    println!("[+] Done!");

    enclave.destroy();
}
