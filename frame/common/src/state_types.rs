use crate::bincode;
use crate::crypto::AccountId;
use crate::local_anyhow::Result;
use crate::localstd::vec::Vec;
use crate::serde::{Deserialize, Serialize};
use crate::serde_bytes;
use crate::serde_json;
use crate::traits::State;

pub trait RawState: Clone + Default {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct StateType(#[serde(with = "serde_bytes")] Vec<u8>);

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
        Self(bincode::serialize(&account_id).unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub enum ReturnState<S: State> {
    Updated(
        #[serde(bound(deserialize = "S: State"))] (Vec<UpdatedState<S>>, Vec<Option<NotifyState>>),
    ),
    Get(#[serde(bound(deserialize = "S: State"))] S),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct UpdatedState<S: State> {
    pub account_id: AccountId,
    pub mem_id: MemId,
    #[serde(deserialize_with = "S::deserialize")]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct NotifyState {
    pub account_id: AccountId,
    pub mem_id: MemId,
    pub state: serde_json::Value,
}

impl NotifyState {
    pub fn new(account_id: AccountId, mem_id: MemId, state: serde_json::Value) -> Self {
        Self {
            account_id,
            mem_id,
            state,
        }
    }
}

/// State identifier stored in memory.
#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, PartialOrd, PartialEq, Default, Eq, Ord, Hash,
)]
#[serde(crate = "crate::serde")]
pub struct MemId(u32);

impl MemId {
    pub fn as_raw(self) -> u32 {
        self.0
    }

    pub fn from_raw(u: u32) -> Self {
        MemId(u)
    }
}

/// Counter for enforcing the order of state transitions
#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, PartialOrd, PartialEq, Default, Eq, Ord, Hash,
)]
#[serde(crate = "crate::serde")]
pub struct StateCounter(u32);

impl StateCounter {
    pub fn new(counter: u32) -> Self {
        Self(counter)
    }
}
