use crate::localstd::{fmt::Debug, vec::Vec};
use crate::serde::{Deserialize, Serialize};
use crate::serde_bytes;

/// A request body to recover path secret from key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "crate::serde")]
pub struct RecoveredPathSecret {
    #[serde(with = "serde_bytes")]
    path_secret: Vec<u8>,
    epoch: u32,
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
}

impl RecoveredPathSecret {
    pub fn new(path_secret: Vec<u8>, epoch: u32, id: Vec<u8>) -> Self {
        RecoveredPathSecret {
            path_secret,
            epoch,
            id,
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn path_secret(&self) -> &[u8] {
        &self.path_secret[..]
    }

    pub fn id(&self) -> &[u8] {
        &self.id[..]
    }
}
