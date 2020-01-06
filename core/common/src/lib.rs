#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
use {
    sgx_tstd as localstd,
};
#[cfg(feature = "std")]
use {
    std as localstd,
};
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

mod crypto;
mod traits;

pub use crate::crypto::*;
pub use crate::traits::*;
