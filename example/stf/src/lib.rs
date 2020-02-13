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

use crate::localstd::{
    io::{self, Read, Write},
    vec::Vec,
};

pub mod value;
pub mod state_type;
pub use crate::value::*;
pub use crate::state_type::*;

/// Trait of each user's state.
pub trait State: Sized + Default + Clone {
    fn new(init: u64) -> Self;

    fn as_bytes(&self) -> io::Result<Vec<u8>>;

    fn from_bytes(bytes: &[u8]) -> io::Result<Self>;

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()>;

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self>;
}
