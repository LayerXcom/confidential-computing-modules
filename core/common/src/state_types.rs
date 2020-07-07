use crate::traits::State;
use crate::localstd::{
    vec::Vec,
    boxed::Box,
};
use crate::local_anyhow::Result;
use crate::crypto::UserAddress;
use codec::{Encode, Decode};
use anonify_types::RawUpdatedState;

pub trait RawState: Encode + Decode + Clone + Default {}

#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType(pub Vec<u8>);

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
