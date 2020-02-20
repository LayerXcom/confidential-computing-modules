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
    fmt,
};
use codec::{Input, Output, Encode, Decode};
use anonify_common::IntoVec;

pub mod value;
pub mod state_type;
pub use crate::value::*;
pub use crate::state_type::*;

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


pub const CIPHERTEXT_SIZE: usize = 88;

#[derive(Clone)]
pub struct Ciphertext([u8; CIPHERTEXT_SIZE]);

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext ")
    }
}

impl Default for Ciphertext {
    fn default() -> Self {
        Ciphertext([0u8; CIPHERTEXT_SIZE])
    }
}

impl IntoVec for Ciphertext {
    fn into_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), CIPHERTEXT_SIZE);
        let mut buf = [0u8; CIPHERTEXT_SIZE];
        buf.copy_from_slice(bytes);

        Ciphertext(buf)
    }

    pub fn from_bytes_iter(bytes: &[u8]) -> impl Iterator<Item=Self> + '_ {
        assert_eq!(bytes.len() % CIPHERTEXT_SIZE, 0);
        let iter_num = bytes.len() / CIPHERTEXT_SIZE;

        (0..iter_num).map(move |i| {
            let mut buf = [0u8; CIPHERTEXT_SIZE];
            let b = &bytes[i*CIPHERTEXT_SIZE..(i+1)*CIPHERTEXT_SIZE];
            buf.copy_from_slice(b);
            Ciphertext(buf)
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
