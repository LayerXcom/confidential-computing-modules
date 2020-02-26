#![crate_type = "lib"]

pub mod dispatcher;
mod bridges;
mod init_enclave;
mod constants;
#[cfg(test)]
mod tests;

use bridges::auto_ffi;
pub use init_enclave::EnclaveDir;
pub use dispatcher::Dispatcher;
