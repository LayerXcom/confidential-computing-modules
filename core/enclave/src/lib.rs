#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate inventory;

mod crypto;
mod state;
mod error;
mod kvs;
mod bridges;
mod context;
mod transaction;
mod config;
mod group_key;

use bridges::ocalls;