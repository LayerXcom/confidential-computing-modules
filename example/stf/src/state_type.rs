//! This module containes application specific components.
//! Following code is an example of simple state transtion for transferable assets.

use crate::State;
use crate::localstd::{
    vec::Vec,
};
use crate::value::Value;
use codec::{Encode, Decode, Input, Output};
pub const STATE_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Encode, Decode)]
pub struct StateType {
    pub raw: Value,
}

impl State for StateType {
    fn new(init: u64) -> Self {
        StateType{
            raw: Value::new(init),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.raw.encode()
    }

    fn from_bytes(bytes: &mut [u8]) -> Result<Self, codec::Error> {
        StateType::decode(&mut &bytes[..])
    }

    fn write_le<O: Output>(&self, writer: &mut O) {
        self.encode_to(writer);
    }

    fn read_le<I: Input>(reader: &mut I) -> Result<Self, codec::Error> {
        StateType::decode(reader)
    }
}

impl StateType {
    pub fn from_state<T: State>(state: T) -> Result<Self, codec::Error>{
        let mut state = state.as_bytes();
        StateType::from_bytes(&mut state)
    }

    pub fn into_state<T: State>(&self) -> Result<T, codec::Error>{
        let mut buf = self.as_bytes();
        T::from_bytes(&mut buf[..])
    }
}
