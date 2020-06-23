#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod crypto;
mod error;
pub mod kvs;
pub mod bridges;
pub mod context;
pub mod transaction;
pub mod config;
mod group_key;
pub mod notify;
pub mod instructions;
