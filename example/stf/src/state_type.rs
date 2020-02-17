//! This module containes application specific components.
//! Following code is an example of simple state transtion for transferable assets.

use crate::State;
use crate::localstd::{
    vec::Vec,
    collections::BTreeMap,
    ops::{Add, Sub},
};
use codec::{Encode, Decode, Input, Output};
pub const STATE_SIZE: usize = 8;

pub trait RawState: Encode + Decode + Clone + Default {}

#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType(Vec<u8>);

#[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, PartialOrd)]
pub struct U64(pub u64);

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
