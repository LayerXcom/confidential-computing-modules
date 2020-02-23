//! This module containes application specific components.
//! Following code is an example of simple state transtion for transferable assets.

use crate::State;
use crate::localstd::{
    vec::Vec,
    collections::BTreeMap,
    ops::{Add, Sub, Mul, Div, Neg},
    convert::TryFrom,
};
use anonify_common::UserAddress;
use codec::{Encode, Decode, Input, Output};

macro_rules! impl_uint {
    ($name:ident, $raw:ident, $size:expr) => {
        #[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash)]
        pub struct $name($raw);

        impl TryFrom<Vec<u8>> for $name {
            type Error = codec::Error;

            fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
                if s.len() == 0 {
                    return Ok(Default::default());
                }
                let mut buf = s;
                $name::from_bytes(&mut buf)
            }
        }

        impl TryFrom<&mut [u8]> for $name {
            type Error = codec::Error;

            fn try_from(s: &mut [u8]) -> Result<Self, Self::Error> {
                if s.len() == 0 {
                    return Ok(Default::default());
                }
                $name::from_bytes(s)
            }
        }

        impl From<$name> for StateType {
            fn from(u: $name) -> Self {
                StateType(u.as_bytes())
            }
        }

        impl TryFrom<StateType> for $name {
            type Error = codec::Error;

            fn try_from(s: StateType) -> Result<Self, Self::Error> {
                if s.0.len() == 0 {
                    return Ok(Default::default());
                }
                let mut buf = s.0;
                $name::from_bytes(&mut buf)
            }
        }

        impl Add for $name {
            type Output = $name;

            fn add(self, other: Self) -> Self {
                let r = self.0 + other.0;
                $name(r)
            }
        }

        impl Sub for $name {
            type Output = $name;

            fn sub(self, other: Self) -> Self {
                let r = self.0 - other.0;
                $name(r)
            }
        }

        impl Mul<$name> for $name {
            type Output = $name;

            fn mul(self, rhs: Self) -> Self {
                let r = self.0 * rhs.0;
                $name(r)
            }
        }

        impl Div<$name> for $name {
            type Output = $name;

            fn div(self, rhs: Self) -> Self {
                let r = self.0 / rhs.0;
                $name(r)
            }
        }

        impl $name {
            pub fn as_raw(&self) -> $raw {
                self.0
            }

            pub fn from_raw(u: $raw) -> Self {
                $name(u)
            }

            pub fn zero() -> Self {
                $name(0)
            }

            pub fn size() -> usize {
                $size as usize
            }
        }
    };
}

impl_uint!(U16, u16, 2);
impl_uint!(U32, u32, 4);
impl_uint!(U64, u64, 8);

pub const STATE_SIZE: usize = 8;

pub trait RawState: Encode + Decode + Clone + Default {}

/// Do not use `as_bytes()` to get raw bytes from `StateType`, just use `StateType.0`.
#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType(Vec<u8>);

impl StateType {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

// TODO: Mapping!(Address, U64);
#[derive(Encode, Decode, Clone, Debug, PartialEq, PartialOrd, Default)]
pub struct Mapping(pub BTreeMap<UserAddress, U64>);

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
