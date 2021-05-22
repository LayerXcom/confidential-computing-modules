//! Small sets of data types for communication between host and enclave.
//!
//! Everything here might appear in both enclave and RDBMS's process memory space.
//! Take care not to take/pass user inputs in/to this crate.
//!
//! Ideally, everything in this crate serves for any RDBMS's extension development.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod aggregate_state;
pub mod enc_type;

mod ecall_cmd;

pub use ecall_cmd::EcallCmd;

#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;
