#![no_std]
#![crate_type = "lib"]

#[macro_use]
extern crate sgx_tstd as std;

mod client;
mod cache;
mod error;
mod https;

pub use https::{HttpsClient, parse_response_attn_report};
pub use error::HttpsEnclaveError as Error;
