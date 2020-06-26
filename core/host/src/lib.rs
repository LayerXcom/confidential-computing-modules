#![crate_type = "lib"]

pub mod dispatcher;
mod bridges;
mod init_enclave;
mod constants;

use bridges::auto_ffi;
pub use init_enclave::EnclaveDir;
pub use dispatcher::Dispatcher;
