#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

pub mod types;
pub use crate::types::*;

#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;
