#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;
#[cfg(feature = "std")]
use anyhow as local_anyhow;
#[cfg(feature = "sgx")]
use sgx_anyhow as local_anyhow;
#[macro_use]
extern crate lazy_static;

pub mod context_switch;
pub mod plugin_types;
pub mod crypto;
pub mod kvs;
pub mod state_types;
pub mod commands;

pub use crate::kvs::*;
