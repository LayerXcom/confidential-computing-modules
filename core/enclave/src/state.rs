//! State transition functions for anonymous asset
use anonify_types::types::*;
use crate::{
    crypto::*,
    kvs::DBValue,
    sealing::NonSealedDbValue,
    error::Result,
};
use std::{
    prelude::v1::*,
    marker::PhantomData,
};

pub trait State { }

/// Curret nonce for state.
/// Priventing from race condition of writing ciphertext to blockchain.
#[derive(Debug)]
pub enum CurrentNonce { }

/// Next nonce for state.
/// It'll be defined deterministically as `next_nonce = Hash(address, current_state, current_nonce)`.
#[derive(Debug)]
pub enum NextNonce { }

/// This struct can be got by decrypting ciphertexts which is stored on blockchain.
/// The secret key is shared among all TEE's enclaves.
/// State and nonce field of this struct should be encrypted before it'll store enclave's in-memory db.
#[derive(Debug, Clone)]
pub struct UserState<S: State, Nonce> {
    address: Address,
    state: S,
    nonce: [u8; 32],
    _marker: PhantomData<Nonce>,
}

// State with NextNonce must not be allowed to access to the database to avoid from
// storing data which have not been considered globally consensused.
impl<S: State> UserState<S, CurrentNonce> {
    pub fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self {
        unimplemented!();
    }

    fn sha256(&self) -> Sha256 {
        unimplemented!();
    }

    pub fn into_db_key(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn into_db_value(&self) -> NonSealedDbValue {
        unimplemented!();
    }

    pub fn from_bytes() -> Self {
        unimplemented!();
    }

    fn encrypt_db_value() {
        unimplemented!();
    }

    fn decrypt_db_value() {
        unimplemented!();
    }
}

impl<S: State> UserState<S, NextNonce> {
    pub fn encrypt(&self, key: &SymmetricKey) -> Result<Ciphertext> {
        // encrypt_aes_256_gcm(, key)
        unimplemented!();
    }

    fn as_bytes(&self) -> &[u8] {
        use byteorder::{ByteOrder, LittleEndian};

        unimplemented!();
    }
}

impl<S: State> From<UserState<S, CurrentNonce>> for UserState<S, NextNonce> {
    fn from(s: UserState<S, CurrentNonce>) -> Self {
        let mut nonce = [0u8; 32];
        //TODO: Cul next nonce.

        UserState {
            address: s.address,
            state: s.state,
            nonce: nonce,
            _marker: PhantomData,
        }
    }
}

