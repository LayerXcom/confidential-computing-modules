//! This module containes application specific components.
//! Following code is an example of simple state transtion for transferable assets.

use crate::State;
use crate::localstd::{
    vec::Vec,
    collections::BTreeMap,
    ops::{Add, Sub},
    convert::TryFrom,
};
use codec::{Encode, Decode, Input, Output};
pub const STATE_SIZE: usize = 8;

pub trait RawState: Encode + Decode + Clone + Default {}

/// Do not use `as_bytes()` to get raw bytes from `StateType`, just use `StateType.0`.
#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType(pub Vec<u8>);

#[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, PartialOrd)]
pub struct U64(pub u64);

impl From<U64> for StateType {
    fn from(u: U64) -> Self {
        StateType(u.as_bytes())
    }
}

impl TryFrom<StateType> for U64 {
    type Error = codec::Error;

    fn try_from(s: StateType) -> Result<Self, Self::Error> {
        let mut buf = s.0;
        U64::from_bytes(&mut buf)
    }
}

impl TryFrom<Vec<u8>> for U64 {
    type Error = codec::Error;

    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        let mut buf = s;
        U64::from_bytes(&mut buf)
    }
}

impl TryFrom<&mut [u8]> for U64 {
    type Error = codec::Error;

    fn try_from(s: &mut [u8]) -> Result<Self, Self::Error> {
        U64::from_bytes(s)
    }
}

impl Add for U64 {
    type Output = U64;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        U64(res)
    }
}

impl Sub for U64 {
    type Output = U64;

    fn sub(self, other: Self) -> Self {
        let res = self.0 - other.0;
        U64(res)
    }
}

#[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub [u8; 20]);

// TODO: Mapping!(Address, U64);
#[derive(Encode, Decode, Clone, Debug, PartialEq, PartialOrd, Default)]
pub struct Mapping(pub BTreeMap<Address, U64>);

impl Mapping {

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_as_bytes() {
        let mut v = U64(10).as_bytes();
        assert_eq!(U64(10), U64::from_bytes(&mut v).unwrap());
    }

    #[test]
    fn test_from_state() {
        assert_eq!(U64(100), U64::from_state(&U64(100)).unwrap());
    }
}
