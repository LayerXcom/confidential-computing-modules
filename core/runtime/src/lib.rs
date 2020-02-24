#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

use codec::{Input, Output, Encode, Decode};
use anonify_common::UserAddress;
use crate::utils::MemId;
use crate::state_type::StateType;
use crate::localstd::{
    fmt,
    vec::Vec,
};

pub mod impls;
pub mod state_type;
pub mod utils;

/// Trait of each user's state.
pub trait State: Sized + Default + Clone + Encode + Decode + fmt::Debug {
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

impl<T: Sized + Default + Clone + Encode + Decode + fmt::Debug> State for T {}

/// A getter of state stored in enclave memory.
pub trait StateGetter {
    /// Get dstate using memory name.
    /// Assumed this is called in user-defined state transition functions.
    fn get<S: State>(&self, key: &UserAddress, name: &str) -> Result<S, codec::Error>;

    /// Get state using memory id.
    /// Assumed this is called by state getting operations from outside enclave.
    fn get_by_id(&self, key: &UserAddress, mem_id: MemId) -> StateType;
}
