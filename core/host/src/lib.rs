#![crate_type = "lib"]
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use init_enclave::EnclaveDir;
use sgx_types::*;

pub use error::HostError as Error;
pub mod prelude;
mod bridges;
mod init_enclave;
mod constants;
mod error;
mod web3;
#[cfg(test)]
mod tests;

use bridges::{ecalls, auto_ffi};
