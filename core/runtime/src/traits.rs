use crate::local_anyhow::{Result, anyhow};
use crate::utils::*;
use crate::localstd::{
    fmt::Debug,
    vec::Vec,
    mem::size_of,
};
use crate::state_type::StateType;
use anonify_common::UserAddress;
use codec::{Input, Output, Encode, Decode};

/// Trait of each user's state.
pub trait State: Sized + Default + Clone + Encode + Decode + Debug {
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

impl<T: Sized + Default + Clone + Encode + Decode + Debug> State for T {}

/// A getter of state stored in enclave memory.
pub trait StateGetter {
    /// Get state using memory id.
    /// Assumed this is called in user-defined state transition functions.
    fn get_trait<S, U>(&self, key: U, mem_id: MemId) -> Result<S>
    where
        S: State,
        U: Into<UserAddress>;

    fn get_type(&self, key: UserAddress, mem_id: MemId) -> StateType;
}

/// Execute state transiton functions from runtime
pub trait RuntimeExecutor<G: StateGetter>: Sized {
    type C: CallKindExecutor<G>;

    fn new(db: G) -> Self;
    fn execute(self, kind: Self::C, my_addr: UserAddress) -> Result<Vec<UpdatedState<StateType>>>;
}

/// Execute state traisiton functions from call kind
pub trait CallKindExecutor<G: StateGetter>: Sized + Encode + Decode + Debug + Clone {
    type R: RuntimeExecutor<G>;

    fn new(id: u32, state: &mut [u8]) -> Result<Self>;
    fn execute(self, runtime: Self::R, my_addr: UserAddress) -> Result<Vec<UpdatedState<StateType>>>;
}

/// A converter from memory name to memory id
pub trait MemNameConverter: Debug {
    fn as_id(name: &str) -> MemId;
}

/// A converter from call name to call id
pub trait CallNameConverter: Debug {
    fn as_id(name: &str) -> u32;
}
