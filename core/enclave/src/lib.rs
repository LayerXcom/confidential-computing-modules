#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

mod crypto;
mod state;
mod error;
mod kvs;
mod bridges;
mod sealing;
mod attestation;
mod context;
mod transaction;
mod cert;
mod group_key;
mod rpc;
#[cfg(debug_assertions)]
mod tests;

use bridges::ocalls;