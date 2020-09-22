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

pub mod impls;
pub mod prelude;
pub mod primitives;
#[cfg(feature = "sgx")]
pub mod traits;

#[cfg(feature = "sgx")]
pub use crate::traits::*;
