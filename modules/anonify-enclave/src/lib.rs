#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod context;
mod crypto;
mod error;
mod group_key;
pub mod instructions;
pub mod kvs;
pub mod notify;
pub mod workflow;
