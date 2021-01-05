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
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;
#[cfg(feature = "sgx")]
use sgx_anyhow as local_anyhow;
#[cfg(feature = "sgx")]
use sgx_libsecp256k1 as local_secp256k1;
#[cfg(feature = "sgx")]
use sgx_log as local_log;
#[cfg(feature = "sgx")]
use sgx_rand as local_rand;
#[cfg(feature = "sgx")]
use sgx_rand_core as local_rand_core;
#[cfg(feature = "sgx")]
use sgx_ring as local_ring;
#[cfg(feature = "std")]
use std_libsecp256k1 as local_secp256k1;
#[cfg(feature = "std")]
use std_log as local_log;
#[cfg(feature = "std")]
use std_rand as local_rand;
#[cfg(feature = "std")]
use std_rand_core as local_rand_core;
#[cfg(feature = "std")]
use std_ring as local_ring;

#[cfg(feature = "sgx")]
mod application;
mod crypto;
#[cfg(feature = "sgx")]
mod group_state;
#[cfg(feature = "sgx")]
pub mod handshake;
#[cfg(feature = "sgx")]
mod ratchet_tree;
#[cfg(feature = "sgx")]
mod tree_math;
// #[cfg(debug_assertions)]
#[cfg(feature = "sgx")]
mod store_path_secrets;
#[cfg(feature = "sgx")]
mod test_funcs;

#[cfg(feature = "sgx")]
pub use crate::application::AppKeyChain;
pub use crate::crypto::dh::{DhPrivateKey, DhPubKey};
pub use crate::crypto::ecies::EciesCiphertext;
#[cfg(all(feature = "sgx", no_std))]
pub use crate::crypto::secrets::SealedPathSecret;
#[cfg(feature = "sgx")]
pub use crate::crypto::secrets::{PathSecret, UnsealedPathSecret};
#[cfg(feature = "sgx")]
pub use crate::group_state::GroupState;
#[cfg(feature = "sgx")]
pub use crate::handshake::Handshake;
#[cfg(feature = "sgx")]
pub use crate::test_funcs::init_path_secret_kvs;
#[cfg(feature = "sgx")]
pub use store_path_secrets::StorePathSecrets;

#[cfg(feature = "sgx")]
#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    use crate::localstd::prelude::v1::*;
    use test_utils::*;

    pub fn run_tests() -> bool {
        check_all_passed!(
            application::tests::run_tests(),
            crypto::ecies::tests::run_tests(),
            crypto::secrets::tests::run_tests(),
        )
    }
}
