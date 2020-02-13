#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

use crate::localstd::{
    vec::Vec,
};
use codec::{Input, Output};

pub mod value;
pub mod state_type;
pub use crate::value::*;
pub use crate::state_type::*;

/// Trait of each user's state.
pub trait State: Sized + Default + Clone {
    fn new(init: u64) -> Self;

    fn as_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &mut [u8]) -> Result<Self, codec::Error>;

    fn write_le<O: Output>(&self, writer: &mut O);

    fn read_le<I: Input>(reader: &mut I) -> Result<Self, codec::Error>;
}
