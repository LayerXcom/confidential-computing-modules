use crate::traits::State;
use crate::localstd::vec::Vec;
use crate::local_anyhow::{Result, anyhow};
use crate::crypto::AccountId;
use codec::{Encode, Decode};

pub trait RawState: Encode + Decode + Clone + Default {}

// TODO: Remove Encode trait bound cause StateType has already be encoded.
// then, implement
// impl<S: State> From<S> for StateType {
//     fn from(state: S) -> Self {
//         StateType::new(state.encode_s())
//     }
// }
#[derive(Clone, Debug, Default, Decode, Encode)]
pub struct StateType(Vec<u8>);

impl StateType {
    pub fn new(v: Vec<u8>) -> Self {
        StateType(v)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<AccountId> for StateType {
    fn from(account_id: AccountId) -> Self {
        Self(account_id.encode_s().into())
    }
}

#[derive(Debug, Clone, Default, Encode, Decode)]
pub struct UpdatedState<S: State> {
    pub account_id: AccountId,
    pub mem_id: MemId,
    pub state: S,
}

impl<S: State> UpdatedState<S> {
    pub fn new(
        account_id: impl Into<AccountId>,
        mem_id: MemId,
        state: impl Into<S>,
    ) -> Result<Self> {
        Ok(UpdatedState {
            account_id: account_id.into(),
            mem_id,
            state: state.into(),
        })
    }

    pub fn from_state_type(update: UpdatedState<StateType>) -> Result<Self> {
        let state = S::decode(&mut &update.state.as_bytes()[..])
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(UpdatedState {
            account_id: update.account_id,
            mem_id: update.mem_id,
            state,
        })
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
