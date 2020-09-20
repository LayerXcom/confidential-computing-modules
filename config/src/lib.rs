#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![allow(unused_imports)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(feature = "sgx")]
use anyhow_sgx as local_anyhow;
#[cfg(feature = "std")]
use anyhow_std as local_anyhow;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as local_serde;
#[cfg(feature = "std")]
use serde_std as local_serde;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use toml_sgx as local_toml;
#[cfg(feature = "std")]
use toml_std as local_toml;
#[macro_use]
extern crate lazy_static;

pub mod constants;

pub use crate::constants::*;
