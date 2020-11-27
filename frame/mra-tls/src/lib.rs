#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

pub mod client;
pub mod config;
mod connection;
pub mod server;
#[cfg(debug_assertions)]
pub mod tests;

pub use client::Client;
pub use server::{Server, RequestHandler};
pub use config::{ClientConfig, ServerConfig};
