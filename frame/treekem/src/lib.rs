#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

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

mod application;
mod crypto;
mod group_state;
pub mod handshake;
mod ratchet_tree;
mod tree_math;
// #[cfg(debug_assertions)]
mod test_funcs;

pub use crate::application::AppKeyChain;
pub use crate::crypto::dh::{DhPrivateKey, DhPubKey};
pub use crate::crypto::ecies::EciesCiphertext;
pub use crate::crypto::secrets::{PathSecret, SealedPathSecret, UnsealedPathSecret};
pub use crate::group_state::GroupState;
pub use crate::handshake::Handshake;
pub use crate::test_funcs::init_path_secret_kvs;

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
