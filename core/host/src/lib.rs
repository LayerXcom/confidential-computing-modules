#![crate_type = "lib"]

pub use error::HostError as Error;
pub mod prelude;
mod bridges;
mod init_enclave;
mod constants;
mod error;
mod web3;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod mock;

use bridges::{ecalls, auto_ffi};
pub use init_enclave::EnclaveDir;
