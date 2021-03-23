use crate::bincode;
use crate::localstd::{boxed::Box, fmt, vec::Vec};
use crate::serde::{Deserialize, Serialize};
use frame_common::TreeKemCiphertext;
use frame_sodium::SodiumCiphertext;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[serde(crate = "crate::serde")]
pub enum CommandCiphertext {
    TreeKem(TreeKemCiphertext),
    EnclaveKey(EnclaveKeyCiphertext),
}

impl Default for CommandCiphertext {
    fn default() -> Self {
        CommandCiphertext::TreeKem(Default::default())
    }
}

/// Application message broadcasted to other members.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(crate = "crate::serde")]
pub struct EnclaveKeyCiphertext {
    encrypted_state: SodiumCiphertext,
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
    pub fn new(encrypted_state: SodiumCiphertext) -> Self {
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
