//! Value Objects and domain services to execute SQL operations / encryption.
//!
//! All of them are designed to be only visible in enclave.
//!
//! Ideally, everything in this crate serves for any RDBMS's extension development.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod aggregate_calc;
pub mod ecall_cmd_handler;
pub mod enclave_context;
pub mod error;
pub mod type_crypt;
