#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

pub mod types;
pub mod traits;

#[cfg(feature = "sgx")]
use sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;

#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
