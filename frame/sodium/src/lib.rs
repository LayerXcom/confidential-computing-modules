#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "std")]
use std as localstd;
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
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

#[cfg(feature = "std")]
use anyhow as local_anyhow;
#[cfg(feature = "sgx")]
use sgx_anyhow as local_anyhow;
#[cfg(feature = "sgx")]
use sgx_crypto_box as crypto_box;
#[cfg(feature = "sgx")]
use sgx_rand_core as rand_core;
#[cfg(feature = "sgx")]
use sgx_xsalsa20poly1305 as xsalsa20poly1305;
#[cfg(feature = "std")]
use std_crypto_box as crypto_box;
#[cfg(feature = "std")]
use std_rand_core as rand_core;
#[cfg(feature = "std")]
use std_xsalsa20poly1305 as xsalsa20poly1305;

mod crypto;
#[cfg(feature = "sgx")]
pub mod rng;
#[cfg(feature = "sgx")]
pub mod sealing;

pub use crypto::{SodiumCiphertext, SodiumPrivateKey, SodiumPubKey, SODIUM_PUBLIC_KEY_SIZE};
