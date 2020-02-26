use crate::traits::State;
use crate::local_anyhow::Result;
use anonify_common::UserAddress;
use codec::{Encode, Decode};

#[derive(Debug, Clone)]
pub struct UpdatedState<S: State> {
    pub address: UserAddress,
    pub mem_id: MemId,
    pub state: S,
}

impl<S: State> UpdatedState<S> {
    pub fn new(address: UserAddress, mem_id: MemId, state: S) -> Self {
        // let mem_id = mem_name_to_id(mem_name);
        UpdatedState {
            address,
            mem_id,
            state
        }
    }
}

pub fn into_trait<S: State>(s: UpdatedState<impl State>) -> Result<UpdatedState<S>> {
    let state = S::from_state(&s.state)?;
    Ok(UpdatedState {
        address: s.address,
        mem_id: s.mem_id,
        state,
    })
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
