use crate::{
    state::{State, UserState, CurrentNonce, NextNonce},
    error::Result,
    kvs::{SigVerificationKVS, MEMORY_DB},
    crypto::UserAddress,
};
use ed25519_dalek::{PublicKey, Signature};
use std::{
    vec::Vec,
    io::{Write, Read},
};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Value(u64);

impl State for Value {
    fn new(init: u64) -> Self {
        Value(init)
    }

    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.write_le(&mut buf)?;
        Ok(buf)
    }

    fn write_le<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, self.0);
        writer.write_all(&buf)?;

        Ok(())
    }

    fn read_le<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let res = LittleEndian::read_u64(&buf);

        Ok(Value(res))
    }
}

use std::ops::Add;

impl Add for Value {
    type Output = Value;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        Value(res)
    }
}

impl Value {
    pub fn into_raw_u64(&self) -> u64 {
        self.0
    }
}

pub trait AnonymousAssetSTF: Sized {
    type S: State;

    fn transfer(
        from: &PublicKey,
        sig: &Signature,
        target: &UserAddress,
        amount: &Self::S,
    ) -> Result<UserState<Self::S, NextNonce>>;
}

impl<S: State> AnonymousAssetSTF for UserState<S, CurrentNonce> {
    type S = Value;

    fn transfer(
        from: &PublicKey,
        sig: &Signature,
        target: &UserAddress,
        amount: &Self::S,
    ) -> Result<UserState<Self::S, NextNonce>> {
        let vec = amount.as_bytes()?;
        let key = UserAddress::from_sig(&vec[..], &sig, &from);
        let my_value = MEMORY_DB.get(&key).unwrap();
        let my_state = UserState::<Self::S, _>::from_db_value(my_value).unwrap();

        let other_value = MEMORY_DB.get(&target).unwrap();



        unimplemented!();
    }
}
