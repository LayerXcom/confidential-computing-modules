//! This module containes application specific components.
//! Following code is an example of simple state transtion for transferable assets.

use crate::State;
use crate::localstd::{
    io::{self, Read, Write, Error, ErrorKind},
    ops::{Add, Sub},
    vec::Vec,
};
use byteorder::{ByteOrder, LittleEndian};
use crate::serde::{Serialize, Deserialize};

const VALUE_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct Value(u64);

impl State for Value {
    fn new(init: u64) -> Self {
        Value(init)
    }

    fn as_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(VALUE_LENGTH);
        self.write_le(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let mut buf = bytes;
        Self::read_le(&mut buf)
    }

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = [0u8; VALUE_LENGTH];
        LittleEndian::write_u64(&mut buf, self.0);
        writer.write_all(&buf)?;

        Ok(())
    }

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; VALUE_LENGTH];
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
    pub fn into_raw(&self) -> u64 {
        self.0
    }

    pub fn from_state<T: State>(state: T) -> io::Result<Self>{
        let state = state.as_bytes()?;
        Value::from_bytes(&state)
    }

    pub fn into_state<T: State>(&self) -> io::Result<T>{
        let buf = self.as_bytes()?;
        T::from_bytes(&buf[..])
    }
}


pub enum CallKind {
    Transfer,
}

// TODO: to be more generalized
pub struct Runtime(pub CallKind);

impl Runtime {
    // TODO: https://docs.rs/web3/0.10.0/src/web3/contract/tokens.rs.html#71-74
    pub fn exec<S: State>(&self, params: (S, S, S)) -> io::Result<(S, S)> {
        match self.0 {
            CallKind::Transfer => {
                let (my_current, other_current, params) =
                    (Value::from_state(params.0)?, Value::from_state(params.1)?, Value::from_state(params.2)?);
                transfer::<S>(my_current, other_current, params)
            },
        }
    }
}

// TODO: Replace Error to our own error type.
/// Devepler defined state transition function for thier applications.
pub fn transfer<S: State>(my_current: Value, other_current: Value, params: Value) -> io::Result<(S, S)> {
    if my_current < params {
        return Err(Error::new(ErrorKind::InvalidData, "You don't have enough balance."));
    }
    let my_update = my_current - params;
    let other_update = other_current + params;

    Ok((my_update.into_state()?, other_update.into_state()?))
}
