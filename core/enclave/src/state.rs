//! State transition functions for anonymous asset
use anonify_types::types::*;
use crate::crypto::*;
use crate::kvs::DBValue;
use crate::sealing::NonSealedDbValue;
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

#[derive(Debug, Clone)]
pub struct Plaintext<S: State, Nonce> {
    address: Address,
    state: S,
    nonce: [u8; 32],
    _marker: PhantomData<Nonce>,
}

// State with NextNonce must not be allowed to access to the database to avoid from
// storing data which have not been considered globally consensused.
impl<S: State> Plaintext<S, CurrentNonce> {
    pub fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self {
        unimplemented!();
    }

    pub fn get_db_key(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn get_db_value(&self) -> NonSealedDbValue {
        unimplemented!();
    }

    pub fn from_bytes() -> Self {
        unimplemented!();
    }
}

impl<S: State> Plaintext<S, NextNonce> {
    pub fn encrypt(&self, key: &SymmetricKey) -> Ciphertext {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        use byteorder::{ByteOrder, LittleEndian};

        unimplemented!();
    }
}

impl<S: State> From<Plaintext<S, CurrentNonce>> for Plaintext<S, NextNonce> {
    fn from(s: Plaintext<S, CurrentNonce>) -> Self {
        let mut nonce = [0u8; 32];
        //TODO: Cul next nonce.

        Plaintext {
            address: s.address,
            state: s.state,
            nonce: nonce,
            _marker: PhantomData,
        }
    }
}

