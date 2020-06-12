#![no_std]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

use anonify_runtime::{
    prelude::*,
    state_type::*,
};
use crate::localstd::{
    vec::Vec,
    collections::BTreeMap,
};
use anonify_common::{UserAddress, OWNER_ADDRESS};
use codec::{Encode, Decode};

pub const MAX_MEM_SIZE: usize = 100;
pub const CIPHERTEXT_SIZE: usize = MAX_MEM_SIZE + 30;



impl_memory! {

}

impl_runtime! {

}
