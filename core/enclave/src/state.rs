//! State transition functions for anonymous asset
use anonify_common::types::*;
use crate::crypto::{AES256GCM, SymmetricKey};
use crate::kvs::DBValue;

pub trait AnonymousAssetSTF {
    fn transfer(from: Address, to: Address, amount: Value);
}

#[derive(Debug, Clone)]
pub struct State {
    address: Address,
    balance: Value,
    randomness: Randomness,
}

impl From<State> for DBValue {
    fn from(s: State) -> Self {
        unimplemented!();
    }
}

impl AES256GCM for State {
    fn encrypt(&self, key: &SymmetricKey) -> Ciphertext {
        unimplemented!();
    }

    fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self {
        unimplemented!();
    }
}

impl AnonymousAssetSTF for State {
    fn transfer(from: Address, to: Address, amount: Value) {
        unimplemented!();
    }
}
