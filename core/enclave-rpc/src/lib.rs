#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

mod client;
mod config;
mod server;
mod transport;
mod service;

use anyhow::Result;
use std::vec::Vec;

pub trait EnclaveHandler {
    fn handle_req(&self, req: &[u8]) -> Result<Vec<u8>>;
}
