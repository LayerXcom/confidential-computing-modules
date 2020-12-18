#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;

use frame_runtime::prelude::*;

pub const MAX_MEM_SIZE: usize = 5000;

impl_memory! {
    (0, "Dummy", U64)
}

impl_runtime! {}
