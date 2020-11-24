#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

pub mod client;
mod config;
mod connection;
pub mod server;
#[cfg(test)]
mod tests;
