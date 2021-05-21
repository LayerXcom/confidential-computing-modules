use serde::{Deserialize, Serialize};

/// Encrypted INTEGER type.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct EncInteger(Vec<u8>);

impl EncInteger {
    /// Get raw representation of encrypted INTEGER.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for EncInteger {
    fn from(encrypted: Vec<u8>) -> Self {
        Self(encrypted)
    }
}
