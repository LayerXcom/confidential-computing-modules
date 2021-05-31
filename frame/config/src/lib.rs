#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
use std as localstd;
#[cfg(all(not(feature = "sgx"), not(feature = "std")))]
extern crate core as localstd;

#[cfg(all(feature = "sgx", not(feature = "std")))]
use pem_sgx as pem;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
use pem_std as pem;

pub mod envs;
#[cfg(feature = "sgx")]
pub mod measurement;

pub use crate::envs::*;
#[cfg(feature = "sgx")]
pub use crate::measurement::EnclaveMeasurement;
