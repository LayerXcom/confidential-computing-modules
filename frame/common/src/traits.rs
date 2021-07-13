use crate::bincode;
use crate::crypto::AccountId;
use crate::local_anyhow::Result;
use crate::localstd::{fmt::Debug, mem::size_of, vec::Vec};
use crate::serde::{de::DeserializeOwned, Serialize};
use crate::state_types::MemId;
use ed25519_dalek::PublicKey;
use tiny_keccak::Keccak;

/// A trait to verify policy to access resources in the enclave
pub trait AccessPolicy: Clone + Debug + DeserializeOwned + Serialize + Default {
    fn verify(&self) -> Result<()>;

    fn into_account_id(&self) -> AccountId;
}

pub trait EnclaveInput {}
pub trait EnclaveOutput {}

/// Trait of each user's state.
pub trait State: Sized + Default + Clone + Debug + DeserializeOwned + Serialize {
    fn encode_s(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    fn decode_s(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(&bytes[..]).map_err(Into::into)
    }

    fn from_state(state: &impl State) -> Result<Self> {
        let state = bincode::serialize(state)?;
        bincode::deserialize(&state[..]).map_err(Into::into)
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }
}

impl<T: Sized + Default + Clone + Debug + DeserializeOwned + Serialize> State for T {}

/// A decoder traits for the types implemented state trait
pub trait StateDecoder: State {
    fn decode_vec(v: Vec<u8>) -> Result<Self>;

    fn decode_mut_bytes(b: &mut [u8]) -> Result<Self>;
}

/// A converter from memory name to memory id
pub trait MemNameConverter: Debug {
    fn as_id(name: &str) -> MemId;
}

pub trait IntoVec {
    fn into_vec(&self) -> Vec<u8>;
}

/// Trait for 256-bits hash functions
pub trait Hash256 {
    fn hash(inp: &[u8]) -> Self;

    fn from_pubkey(pubkey: &PublicKey) -> Self;
}

pub trait StateVector {}

/// A trait that will hash using Keccak256 the object it's implemented on.
pub trait Keccak256<T> {
    /// This will return a sized object with the hash
    fn keccak256(&self) -> T
    where
        T: Sized;
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
