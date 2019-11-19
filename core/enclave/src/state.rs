//! State transition functions for anonymous asset
use anonify_common::types::*;
use crate::crypto::*;
use crate::kvs::DBValue;
use std::prelude::v1::*;

pub trait AnonymousAssetSTF {
    fn transfer(from: PubKey, to: PubKey, amount: Value) -> State<NewRand>;
}

pub struct OldRand([u8; 32]);
pub struct NewRand([u8; 32]);

#[derive(Debug, Clone)]
pub struct State<R> {
    pubkey: PubKey,
    balance: Value,
    randomness: R,
}

// State with NewRand must not be allowed to access to the database to avoid from
// storing data which have not been considered globally consensused.
impl State<OldRand> {
    pub fn get_db_key(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn get_db_value(&self) -> Vec<u8> {
        unimplemented!();
    }
}

impl From<State<OldRand>> for State<NewRand> {
    fn from(s: State<OldRand>) -> Self {
        let mut rand = [0u8; 32];
        rng_gen(&mut rand).expect("Failt to generate randomness.");
        State {
            pubkey: s.pubkey,
            balance: s.balance,
            randomness: NewRand(rand),
        }
    }
}

// impl AES256GCM for State {
//     fn encrypt(&self, key: &SymmetricKey) -> Ciphertext {
//         unimplemented!();
//     }

//     fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self {
//         unimplemented!();
//     }
// }

impl State<NewRand> {
    fn encrypt(&self, key: &SymmetricKey) -> Ciphertext {
        unimplemented!();
    }
}

impl State<OldRand> {
    fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self {
        unimplemented!();
    }
}

impl AnonymousAssetSTF for State<OldRand> {
    fn transfer(from: PubKey, to: PubKey, amount: Value) -> State<NewRand> {
        unimplemented!();
    }
}
