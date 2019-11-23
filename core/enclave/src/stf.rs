use crate::{
    state::{State, UserState, CurrentNonce, NextNonce},
    error::Result,
};
use secp256k1::PublicKey;
use std::io::{Write, Read};

pub struct Value(u64);

impl State for Value {
    fn write<W: Write>(&self, mut writer: W) -> Result<()> {
        unimplemented!();
    }

    fn read<R: Read>(mut reader: R) -> Result<Self> {
        unimplemented!();
    }
}

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
