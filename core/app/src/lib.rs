#![crate_type = "lib"]
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use init_enclave::EnclaveDir;
use auto_ffi::ecall_get_state;

mod init_enclave;
mod ocalls;
mod constants;
mod equote;
mod error;
mod attestation;
mod web3;
mod auto_ffi;
#[cfg(test)]
mod tests;

// pub fn get_state() {
//     let state = unsafe {
//         ecall_get_state()
//     };
// }

fn init_enclave() {

    let enclave = EnclaveDir::new().init_enclave().unwrap();
    let eid = enclave.geteid();

    println!("[+] Done!");

    enclave.destroy();
}
