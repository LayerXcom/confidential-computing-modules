//! This module containes application specific components.
//! Following code is an example of simple state transtion for transferable assets.

use crate::State;
use crate::localstd::{
    vec::Vec,
    ops::{Add, Sub},
};
use codec::{Encode, Decode, Input, Output};
pub const STATE_SIZE: usize = 8;

pub trait RawState: Encode + Decode + Clone + Default {}

#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType {
    pub raw: Vec<u8>,
}

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
