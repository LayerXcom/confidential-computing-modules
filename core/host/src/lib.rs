#![crate_type = "lib"]
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;

use init_enclave::EnclaveDir;
use sgx_types::*;

pub use error::HostError as Error;
pub mod prelude;
mod init_enclave;
mod ocalls;
mod ecalls;
mod constants;
mod error;
mod web3;
mod auto_ffi;
#[cfg(test)]
mod tests;
