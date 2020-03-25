//! `CIPHERTEXT_SIZE` is dynamically changed, depending on each applications
//! ,so the ciphertext type is defined in a library inhereted from app library.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

use crate::localstd::vec::Vec;
pub use app::*;
use anonify_common::IntoVec;

#[derive(Clone, Debug, Default)]
pub struct Ciphertext(pub Vec<u8>);

impl From<Vec<u8>> for Ciphertext {
    fn from(c: Vec<u8>) -> Self {
        Ciphertext(c)
    }
}

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
