#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "sgx")]
use anyhow_sgx as local_anyhow;
#[cfg(feature = "std")]
use anyhow_std as local_anyhow;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;

pub mod impls;
pub mod prelude;
pub mod primitives;
#[cfg(feature = "sgx")]
pub mod traits;

#[cfg(feature = "sgx")]
pub use crate::traits::*;
use crate::serde::{Serialize, de::DeserializeOwned};

/// A marker trait for generalizing the command types of the runtime.
pub trait RuntimeCommand: Serialize + DeserializeOwned {}
