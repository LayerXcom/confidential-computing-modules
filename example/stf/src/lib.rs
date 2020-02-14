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
use codec::{Input, Output, Encode, Decode};

pub mod value;
pub mod state_type;
pub use crate::value::*;
pub use crate::state_type::*;

/// Trait of each user's state.
pub trait State: Sized + Default + Clone + Encode + Decode {
    fn as_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    fn from_bytes(bytes: &mut [u8]) -> Result<Self, codec::Error> {
        Self::decode(&mut &bytes[..])
    }

    fn write_le<O: Output>(&self, writer: &mut O) {
        self.encode_to(writer)
    }

    fn read_le<I: Input>(reader: &mut I) -> Result<Self, codec::Error> {
        Self::decode(reader)
    }

    fn from_state(state: &impl State) -> Result<Self, codec::Error> {
        let mut state = state.as_bytes();
        Self::from_bytes(&mut state)
    }
}

impl<T: Sized + Default + Clone + Encode + Decode> State for T {}
