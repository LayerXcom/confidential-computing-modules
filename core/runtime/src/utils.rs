use crate::traits::State;
use crate::local_anyhow::Result;
use crate::localstd::boxed::Box;
use anonify_common::UserAddress;
use anonify_types::RawUpdatedState;
use codec::{Encode, Decode};

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
        state: impl Into<S>,
    ) -> Self {
        UpdatedState {
            address: address.into(),
            mem_id,
            state: state.into(),
        }
    }
}

impl<S: State> From<RawUpdatedState> for UpdatedState<S> {
    fn from(raw: RawUpdatedState) -> Self {
        let box_state = raw.state as *mut Box<[u8]>;
        let mut state = unsafe { Box::from_raw(box_state) };
        let state = S::from_bytes(&mut state)
            .expect("Failed to read raw pointer of state in RawUpdatedState");

        UpdatedState {
            address: UserAddress::from_array(raw.address),
            mem_id: MemId::from_raw(raw.mem_id),
            state,
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
