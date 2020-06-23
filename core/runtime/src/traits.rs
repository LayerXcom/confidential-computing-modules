use crate::local_anyhow::{Result, anyhow};
use crate::utils::*;
use crate::localstd::{
    fmt,
    vec::Vec,
    mem::size_of,
};
use crate::state_type::StateType;
use anonify_common::UserAddress;
use codec::{Input, Output, Encode, Decode};

/// Trait of each user's state.
pub trait State: Sized + Default + Clone + Encode + Decode + fmt::Debug {
    fn as_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    fn from_bytes(bytes: &mut [u8]) -> Result<Self> {
        Self::decode(&mut &bytes[..])
            .map_err(|e| anyhow!("{:?}", e))
    }

    fn write_le<O: Output>(&self, writer: &mut O) {
        self.encode_to(writer)
    }

    fn read_le<I: Input>(reader: &mut I) -> Result<Self> {
        Self::decode(reader)
            .map_err(|e| anyhow!("{:?}", e))
    }

    fn from_state(state: &impl State) -> Result<Self> {
        let mut state = state.as_bytes();
        Self::from_bytes(&mut state)
    }

    fn size(&self) -> usize { size_of::<Self>() }
}

impl<T: Sized + Default + Clone + Encode + Decode + fmt::Debug> State for T {}

/// A getter of state stored in enclave memory.
pub trait StateGetter {
    /// Get state using memory id.
    /// Assumed this is called in user-defined state transition functions.
    fn get<S: State>(&self, key: impl Into<UserAddress>,  mem_id: MemId) -> Result<S>;
}

pub trait CallKindConverter: Sized {
    fn from_call_id(id: u32, state: &mut [u8]) -> Result<Self>;
    fn find(self, my_addr: UserAddress) -> Result<Vec<UpdatedState<StateType>>>;
}

pub trait StateTransition: Sized {
    type G: StateGetter;
    type C: CallKindConverter;

    fn new(db: Self::G) -> Self;
    fn call(self, kind: Self::C, my_addr: UserAddress) -> Result<Vec<UpdatedState<StateType>>>;
}
