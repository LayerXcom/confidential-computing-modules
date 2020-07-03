use crate::localstd::{
    vec::Vec,
    fmt::Debug,
    mem::size_of,
};
use crate::state_types::MemId;
use crate::local_anyhow::{Result, anyhow};
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

/// A converter from memory name to memory id
pub trait MemNameConverter: Debug {
    fn as_id(name: &str) -> MemId;
}

/// A converter from call name to call id
pub trait CallNameConverter: Debug {
    fn as_id(name: &str) -> u32;
}

pub trait IntoVec {
    fn into_vec(&self) -> Vec<u8>;
}
