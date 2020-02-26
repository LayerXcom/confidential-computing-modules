#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(feature = "std")]
use anyhow as local_anyhow;
#[cfg(feature = "sgx")]
use sgx_anyhow as local_anyhow;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

pub mod state_type;
pub mod impls;
pub mod utils;
pub mod prelude;
pub mod traits;

pub use crate::state_type::*;
pub use crate::traits::*;
