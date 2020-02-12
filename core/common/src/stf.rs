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
use crate::value::Value;

pub const STATE_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct StateType {
    raw: Value,
}

impl State for StateType {
    fn new(init: u64) -> Self {
        StateType{
            raw: Value::new(init),
        }
    }

    fn as_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(STATE_SIZE);
        self.write_le(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let mut buf = bytes;
        Self::read_le(&mut buf)
    }

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = [0u8; STATE_SIZE];
        LittleEndian::write_u64(&mut buf, self.into_raw());
        writer.write_all(&buf)?;

        Ok(())
    }

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; STATE_SIZE];
        reader.read_exact(&mut buf)?;
        let res = LittleEndian::read_u64(&buf);

        Ok(StateType{
            raw: Value::new(res),
        })
    }
}

impl Add for StateType {
    type Output = StateType;

    fn add(self, other: Self) -> Self {
        let res = self.into_raw() + other.into_raw();
        StateType{
            raw: Value::new(res)
        }
    }
}

impl Sub for StateType {
    type Output = StateType;

    fn sub(self, other: Self) -> Self {
        let res = self.into_raw() - other.into_raw();
        StateType{
            raw: Value::new(res)
        }
    }
}

impl StateType {
    pub fn into_raw(self) -> u64 {
        self.into_raw()
    }

    pub fn from_state<T: State>(state: T) -> io::Result<Self>{
        let state = state.as_bytes()?;
        StateType::from_bytes(&state)
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
                    (StateType::from_state(params.0)?, StateType::from_state(params.1)?, StateType::from_state(params.2)?);
                transfer::<S>(my_current, other_current, params)
            },
        }
    }
}

// TODO: Replace Error to our own error type.
/// Devepler defined state transition function for thier applications.
pub fn transfer<S: State>(my_current: StateType, other_current: StateType, params: StateType) -> io::Result<(S, S)> {
    if my_current < params {
        return Err(Error::new(ErrorKind::InvalidData, "You don't have enough balance."));
    }
    let my_update = my_current - params;
    let other_update = other_current + params;

    Ok((my_update.into_state()?, other_update.into_state()?))
}
