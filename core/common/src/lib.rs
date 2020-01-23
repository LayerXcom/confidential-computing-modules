#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
use sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;

mod crypto;
mod traits;
pub mod kvs;
pub mod stf;

pub use crate::crypto::*;
pub use crate::traits::*;
