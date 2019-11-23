use crate::state::{State, UserState, CurrentNonce, NextNonce};
use secp256k1::PublicKey;

pub struct Value(u64);

impl State for Value { }

pub trait AnonymousAssetSTF {
    type S: State;

    fn transfer(from: PublicKey, to: PublicKey, amount: Self::S) -> UserState<Self::S, NextNonce>;
}

impl<S: State> AnonymousAssetSTF for UserState<S, CurrentNonce> {
    type S = Value;

    fn transfer(from: PublicKey, to: PublicKey, amount: Self::S) -> UserState<Self::S, NextNonce> {
        unimplemented!();
    }
}
