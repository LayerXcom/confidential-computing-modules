use crate::bincode;
use crate::localstd::{boxed::Box, fmt, vec::Vec};
use crate::serde::{Deserialize, Serialize};
use crate::serde_bytes;

/// Application message broadcasted to other members.
#[derive(Clone, Serialize, Deserialize, Eq, Ord, Hash, Default)]
#[serde(crate = "crate::serde")]
pub struct EnclaveKeyCiphertext {
    #[serde(with = "serde_bytes")]
    encrypted_state: Vec<u8>,
}

impl fmt::Debug for EnclaveKeyCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnclaveKeyCiphertext {{ encrypted_state: 0x{} }}",
            hex::encode(&self.encrypted_state)
        )
    }
}

impl EnclaveKeyCiphertext {
    pub fn new(encrypted_state: Vec<u8>) -> Self {
        EnclaveKeyCiphertext { encrypted_state }
    }

    pub fn decode(bytes: &[u8]) -> crate::localstd::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(&bytes[..])
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    pub fn encrypted_state_ref(&self) -> &[u8] {
        &self.encrypted_state
    }
}
