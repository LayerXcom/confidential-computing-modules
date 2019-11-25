#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate clap;

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
mod term;
mod config;

fn main() {




    let enclave = EnclaveDir::new().init_enclave().unwrap();

    println!("[+] Done!");

    enclave.destroy();
}
