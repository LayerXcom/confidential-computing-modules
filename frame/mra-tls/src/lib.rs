#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

mod cert;
pub mod client;
pub mod config;
mod connection;
mod error;
mod key;
pub mod key_vault;
pub mod server;
#[cfg(debug_assertions)]
pub mod tests;
mod verifier;

pub use client::Client;
pub use config::{AttestedTlsConfig, ClientConfig, ServerConfig};
pub use error::MraTLSError;
pub use server::{RequestHandler, Server};
