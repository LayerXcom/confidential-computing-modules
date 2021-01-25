#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

#[cfg(feature = "std")]
use anyhow as local_anyhow;
#[cfg(feature = "sgx")]
use sgx_anyhow as local_anyhow;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use base64_sgx as base64;
#[cfg(feature = "std")]
use base64_std as base64;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use bincode_sgx as bincode;
#[cfg(feature = "std")]
use bincode_std as bincode;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_bytes_sgx as serde_bytes;
#[cfg(feature = "std")]
use serde_bytes_std as serde_bytes;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;
#[cfg(feature = "sgx")]
use sgx_rand as local_rand;
#[cfg(feature = "sgx")]
use sgx_rand_core as local_rand_core;
#[cfg(feature = "std")]
use std_rand as local_rand;
#[cfg(feature = "std")]
use std_rand_core as local_rand_core;
#[cfg(feature = "std")]
use std_ring as local_ring;
#[cfg(feature = "sgx")]
use sgx_ring as local_ring;
#[cfg(feature = "std")]
use std_libsecp256k1 as local_secp256k1;
#[cfg(feature = "sgx")]
use sgx_libsecp256k1 as local_secp256k1;

pub use crate::dh::{DhPrivateKey, DhPubKey};
pub use crate::ecies::EciesCiphertext;

pub mod dh;
pub mod ecies;
pub mod hkdf;
pub mod hmac;

#[cfg(feature = "std")]
pub mod wasm;

pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

pub trait CryptoRng: crate::local_rand::RngCore + crate::local_rand::CryptoRng {}
impl<T> CryptoRng for T where T: crate::local_rand::RngCore + crate::local_rand::CryptoRng {}

#[cfg(feature = "sgx")]
#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    use crate::localstd::prelude::v1::*;
    use test_utils::*;

    pub fn run_tests() -> bool {
        check_all_passed!(
            ecies::tests::run_tests(),
        )
    }
}
