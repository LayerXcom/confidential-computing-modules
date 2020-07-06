use crate::traits::State;
use crate::localstd::{
    vec::Vec,
    collections::BTreeMap,
    ops::{Add, Sub, Mul, Div},
    convert::TryFrom,
    mem::size_of,
    boxed::Box,
};
use crate::local_anyhow::{Result, Error, anyhow};
use crate::crypto::UserAddress;
use codec::{Encode, Decode};
use anonify_types::RawUpdatedState;

macro_rules! impl_uint {
    ($name:ident, $raw:ident) => {
        #[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash)]
        pub struct $name($raw);

        impl TryFrom<Vec<u8>> for $name {
            type Error = Error;

            fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
                if s.len() == 0 {
                    return Ok(Default::default());
                }
                let mut buf = s;
                $name::decode_s(&mut buf)
            }
        }

        impl TryFrom<&mut [u8]> for $name {
            type Error = Error;

            fn try_from(s: &mut [u8]) -> Result<Self, Self::Error> {
                if s.len() == 0 {
                    return Ok(Default::default());
                }
                $name::decode_s(s)
            }
        }

        impl From<$name> for StateType {
            fn from(u: $name) -> Self {
                StateType(u.encode_s())
            }
        }

        impl TryFrom<StateType> for $name {
            type Error = Error;

            fn try_from(s: StateType) -> Result<Self, Self::Error> {
                if s.0.len() == 0 {
                    return Ok(Default::default());
                }
                let mut buf = s.0;
                $name::decode_s(&mut buf)
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
        }
    };
}

impl_uint!(U16, u16);
impl_uint!(U32, u32);
impl_uint!(U64, u64);

#[derive(Encode, Decode, Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Bytes(Vec<u8>);

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

impl Bytes {
    pub fn new(inner: Vec<u8>) -> Self {
        Bytes(inner)
    }

    pub fn size(&self) -> usize {
        self.0.len() * size_of::<u8>()
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.0
    }
}

impl From<Bytes> for StateType {
    fn from(bs: Bytes) -> Self {
        StateType(bs.0.encode_s())
    }
}

pub trait RawState: Encode + Decode + Clone + Default {}

#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType(Vec<u8>);

impl StateType {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<UserAddress> for StateType {
    fn from(address: UserAddress) -> Self {
        Self(address.encode_s().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_encode() {
        let mut v = U64(10).encode_s();
        assert_eq!(U64(10), U64::decode_s(&mut v).unwrap());
    }

    #[test]
    fn test_from_state() {
        assert_eq!(U64(100), U64::from_state(&U64(100)).unwrap());
    }

    #[test]
    fn test_size() {
        assert_eq!(U16(0).size(), 2);
        assert_eq!(U32(0).size(), 4);
        assert_eq!(U64(0).size(), 8);
    }
}

#[derive(Encode, Decode, Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Approved(BTreeMap<UserAddress, U64>);

impl Approved {
    pub fn new(inner: BTreeMap<UserAddress, U64>) -> Self {
        Approved(inner)
    }

    pub fn total(&self) -> U64 {
        let sum = self.0.iter()
            .fold(U64(0), |acc, (_, &amount)| acc + amount);
        sum
    }

    pub fn approve(&mut self, user_address: UserAddress, amount: U64) {
        match self.allowance(&user_address) {
            Some(&existing_amount) => {
                self.0.insert(user_address, existing_amount + amount);
            }
            None => {
                self.0.insert(user_address, amount);
            }
        }
    }

    pub fn consume(&mut self, user_address: UserAddress, amount: U64) -> Result<(), Error> {
        match self.allowance(&user_address) {
            Some(&existing_amount) => {
                if existing_amount < amount {
                    return Err(anyhow!(
                    "{:?} doesn't have enough balance to consume {:?}.",
                     user_address,
                     amount,
                     ).into());
                }
                self.0.insert(user_address, existing_amount - amount);
                Ok(())
            }
            None => return Err(anyhow!("{:?} doesn't have any balance.", user_address).into())
        }
    }

    pub fn allowance(&self, user_address: &UserAddress) -> Option<&U64> {
        self.0.get(user_address)
    }

    pub fn size(&self) -> usize {
        self.0.len() * (UserAddress::default().size() + U64::default().size())
    }
}

impl From<Approved> for StateType {
    fn from(a: Approved) -> Self {
        StateType(a.0.encode_s())
    }
}

impl TryFrom<Vec<u8>> for Approved {
    type Error = Error;

    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        if s.len() == 0 {
            return Ok(Default::default());
        }
        let mut buf = s;
        Approved::decode_s(&mut buf)
    }
}


#[derive(Debug, Clone, Default)]
pub struct UpdatedState<S: State> {
    pub address: UserAddress,
    pub mem_id: MemId,
    pub state: S,
}

impl<S: State> UpdatedState<S> {
    pub fn new(
        address: impl Into<UserAddress>,
        mem_id: MemId,
        state: impl State,
    ) -> Result<Self> {
        let state = S::from_state(&state)?;

        Ok(UpdatedState {
            address: address.into(),
            mem_id,
            state,
        })
    }
}

impl<S: State> From<RawUpdatedState> for UpdatedState<S> {
    fn from(raw: RawUpdatedState) -> Self {
        let box_state = raw.state as *mut Box<[u8]>;
        let mut state = unsafe { Box::from_raw(box_state) };
        let state = S::decode_s(&mut state)
            .expect("Failed to read raw pointer of state in RawUpdatedState");

        UpdatedState {
            address: UserAddress::from_array(raw.address),
            mem_id: MemId::from_raw(raw.mem_id),
            state,
        }
    }
}

/// State identifier stored in memory.
#[derive(Encode, Decode, Debug, Clone, Copy, PartialOrd, PartialEq, Default, Eq, Ord, Hash)]
pub struct MemId(u32);

impl MemId {
    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(u: u32) -> Self {
        MemId(u)
    }
}
