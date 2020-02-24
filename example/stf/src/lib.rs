#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[macro_use]
extern crate lazy_static;
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

impl<S: State> UpdatedState<S> {
    pub fn new(address: UserAddress, mem_name: &str, state: S) -> Self {
        let mem_id = mem_name_to_id(mem_name);
        UpdatedState {
            address,
            mem_id,
            state
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Ciphertext(pub Vec<u8>);

impl IntoVec for Ciphertext {
    fn into_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), *CIPHERTEXT_SIZE);

        Ciphertext(bytes.to_vec())
    }

    pub fn from_bytes_iter(bytes: &[u8]) -> impl Iterator<Item=Self> + '_ {
        assert_eq!(bytes.len() % (*CIPHERTEXT_SIZE), 0);
        let iter_num = bytes.len() / (*CIPHERTEXT_SIZE);

        (0..iter_num).map(move |i| {
            let buf = &bytes[i*(*CIPHERTEXT_SIZE)..(i+1)*(*CIPHERTEXT_SIZE)];

            Ciphertext(buf.to_vec())
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
