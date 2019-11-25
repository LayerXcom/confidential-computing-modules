use serde::{Deserialize, Serialize};
 use smallvec::SmallVec;
 
mod constants;
mod derive;
mod disk;
mod error;
mod keyfile;

/// Serializable and deserializable bytes
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct SerdeBytes(
    #[serde(with = "serde_bytes")]
    pub Vec<u8>
);

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
