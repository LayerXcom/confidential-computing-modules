//! State transition functions for anonymous asset
use anonify_types::types::*;
use crate::crypto::*;
use crate::kvs::DBValue;
use crate::sealing::DbValue;
use std::prelude::v1::*;
use secp256k1::PublicKey;

pub trait AnonymousAssetSTF {
    fn transfer(from: PublicKey, to: PublicKey, amount: Value) -> State<NewRand>;
}

pub struct OldRand([u8; 32]);
pub struct NewRand([u8; 32]);

#[derive(Debug, Clone)]
pub struct State<R> {
    pubkey: PublicKey,
    balance: Value,
    randomness: R,
}

// State with NewRand must not be allowed to access to the database to avoid from
// storing data which have not been considered globally consensused.
impl State<OldRand> {
    pub fn get_db_key(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn get_db_value(&self) -> DbValue {
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
    fn transfer(from: PublicKey, to: PublicKey, amount: Value) -> State<NewRand> {
        unimplemented!();
    }
}
