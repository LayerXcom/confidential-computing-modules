#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use bincode_sgx as bincode;
#[cfg(feature = "std")]
use bincode_std as bincode;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_bytes_sgx as serde_bytes;
#[cfg(feature = "std")]
use serde_bytes_std as serde_bytes;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_json_sgx as serde_json;
#[cfg(feature = "std")]
use serde_json_std as serde_json;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;

pub mod cmd;
pub mod types;
pub use crate::types::*;
pub mod ciphertexts;

pub use ciphertexts::*;
