use crate::error::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

mod constants;
mod derive;
mod disk;
mod error;
mod keyfile;

pub use disk::{KeystoreDirectory, WalletDirectory};
pub use error::WalletError as Error;
pub use keyfile::KeyFile;

/// Operations in a wallet directory
pub trait DirOperations {
    /// Insert a new keyfile to this wallet directory.
    fn insert<R: Rng>(&self, keyfile: &mut KeyFile, rng: &mut R) -> Result<()>;

    /// Load a keyfile
    fn load(&self, keyfile_name: &str) -> Result<KeyFile>;

    /// Load all keyfiles in this wallet directory.
    fn load_all(&self) -> Result<Vec<KeyFile>>;

    /// Remove a keyfile from this wallet directory.
    fn remove(&self, keyfile: &mut KeyFile) -> Result<()>;
}

/// Serializable and deserializable bytes
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct SerdeBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl From<Vec<u8>> for SerdeBytes {
    fn from(v: Vec<u8>) -> Self {
        SerdeBytes(v)
    }
}

impl From<SmallVec<[u8; 32]>> for SerdeBytes {
    fn from(v: SmallVec<[u8; 32]>) -> Self {
        SerdeBytes(v.into_vec())
    }
}

impl From<[u8; 32]> for SerdeBytes {
    fn from(v: [u8; 32]) -> Self {
        SerdeBytes(v.to_vec())
    }
}

impl From<[u8; 16]> for SerdeBytes {
    fn from(v: [u8; 16]) -> Self {
        SerdeBytes(v.to_vec())
    }
}

impl From<&[u8]> for SerdeBytes {
    fn from(v: &[u8]) -> Self {
        SerdeBytes(v.to_vec())
    }
}
