#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(feature = "sgx")]
use once_cell_sgx as local_once_cell;
#[cfg(feature = "std")]
use once_cell_std as local_once_cell;

pub mod envs;
#[cfg(feature = "sgx")]
pub mod measurement;

pub use crate::envs::*;
#[cfg(feature = "sgx")]
pub use crate::measurement::EnclaveMeasurement;
