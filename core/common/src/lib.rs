#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
mod std {
    pub use ::sgx_tstd::*;
}

mod crypto;

pub use crate::crypto::*;
