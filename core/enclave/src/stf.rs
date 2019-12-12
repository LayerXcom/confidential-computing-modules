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
    ops::{Add, Sub},
    convert::TryInto,
};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd)]
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

impl Add for Value {
    type Output = Value;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        Value(res)
    }
}

impl Sub for Value {
    type Output = Value;

    fn sub(self, other: Self) -> Self {
        let res = self.0 - other.0;
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

    fn init(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        amount: Self::S,
    ) -> Result<UserState<Self::S, NextNonce>>;

    fn transfer(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        target: UserAddress,
        amount: Self::S,
    ) -> Result<(UserState<Self::S, NextNonce>, UserState<Self::S, NextNonce>)>;
}

impl<S: State> AnonymousAssetSTF for UserState<S, CurrentNonce> {
    type S = Value;

    fn init(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        total_supply: Self::S,
    ) -> Result<UserState<Self::S, NextNonce>> {
        let address = UserAddress::from_sig(&msg, &sig, &from);
        let state: UserState<Self::S, NextNonce> = UserState::new(address, total_supply)?;

        Ok(state)
    }

    fn transfer(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        target: UserAddress,
        amount: Self::S,
    ) -> Result<(UserState<Self::S, NextNonce>, UserState<Self::S, NextNonce>)> {
        let my_addr = UserAddress::from_sig(&msg, &sig, &from);
        let my_value = MEMORY_DB.get(&my_addr).unwrap();
        let other_value = MEMORY_DB.get(&target).unwrap();

        let my_current_balance = UserState::<Self::S, _>::from_db_value(my_value.clone())?.0;
        assert!(amount > my_current_balance);
        let other_current_balance = UserState::<Self::S, _>::from_db_value(other_value.clone())?.0;

        let my_current_state = UserState::from_address_and_db_value(my_addr, my_value)?;
        let other_current_state = UserState::from_address_and_db_value(target, other_value)?;

        let my_updated: UserState<Self::S, NextNonce> = my_current_state
            .update_inner_state(my_current_balance - amount).try_into()?;
        let other_updated: UserState<Self::S, NextNonce> = other_current_state
            .update_inner_state(other_current_balance + amount).try_into()?;

        Ok((my_updated, other_updated))
    }
}
