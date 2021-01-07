#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod error;
mod handlers;
pub mod server;
pub mod context;

pub mod workflow {
    pub use crate::server::{ServerStarter, ServerStopper};
}
