use crate::localstd::{
    vec::Vec,
    fmt::Debug,
    mem::size_of,
};
use crate::state_types::MemId;
use crate::local_anyhow::{Result, anyhow};
use codec::{Encode, Decode};
use ed25519_dalek::PublicKey;
use tiny_keccak::Keccak;

pub trait EcallInput {}
pub trait EcallOutput {}

/// Trait of each user's state.
pub trait State: Sized + Default + Clone + Encode + Decode + Debug {
    fn encode_s(&self) -> Vec<u8> {
        self.encode()
    }

    fn decode_s(bytes: &mut [u8]) -> Result<Self> {
        Self::decode(&mut &bytes[..])
            .map_err(|e| anyhow!("{:?}", e))
    }

    fn from_state(state: &impl State) -> Result<Self> {
        let mut state = state.encode();
        Self::decode_s(&mut state)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
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

/// Trait for 256-bits hash functions
pub trait Hash256 {
    fn hash(inp: &[u8]) -> Self;

    fn from_pubkey(pubkey: &PublicKey) -> Self;
}

/// A trait that will hash using Keccak256 the object it's implemented on.
pub trait Keccak256<T> {
    /// This will return a sized object with the hash
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(result.as_mut());
        result
    }
}
