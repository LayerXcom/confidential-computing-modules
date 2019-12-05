use crate::{
    state::{State, UserState, CurrentNonce, NextNonce},
    error::Result,
    kvs::SigVerificationKVS,
};
use ed25519_dalek::PublicKey;
use std::io::{Write, Read};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Value(u64);

impl State for Value {
    fn new(init: u64) -> Self {
        Value(init)
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

impl Value {
    pub fn into_raw_u64(&self) -> u64 {
        self.0
    }
}

pub trait AnonymousAssetSTF {
    type S: State;
    type KVS: SigVerificationKVS;

    fn transfer(from: PublicKey, to: PublicKey, amount: Self::S) -> UserState<Self::S, NextNonce>;
}

impl<S: State> AnonymousAssetSTF for UserState<S, CurrentNonce> {
    type S = Value;
    type KVS = MemoryKVS;

    fn transfer(from: PublicKey, to: PublicKey, amount: Self::S) -> UserState<Self::S, NextNonce> {
        
        unimplemented!();
    }
}
