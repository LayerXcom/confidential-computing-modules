use crate::state::{State, Plaintext, CurrentNonce, NextNonce};
use secp256k1::PublicKey;

pub struct Value(u64);

impl State for Value { }

pub trait AnonymousAssetSTF {
    type S: State;

    fn transfer(from: PublicKey, to: PublicKey, amount: Self::S) -> Plaintext<Self::S, NextNonce>;
}

impl<S: State> AnonymousAssetSTF for Plaintext<S, CurrentNonce> {
    type S = Value;

    fn transfer(from: PublicKey, to: PublicKey, amount: Self::S) -> Plaintext<Self::S, NextNonce> {
        unimplemented!();
    }
}
