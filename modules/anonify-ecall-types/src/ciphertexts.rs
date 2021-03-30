use crate::bincode;
use crate::localstd::{boxed::Box, fmt, vec::Vec};
use crate::serde::{Deserialize, Serialize};
use frame_common::TreeKemCiphertext;
use frame_sodium::SodiumCiphertext;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
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
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(crate = "crate::serde")]
pub struct EnclaveKeyCiphertext {
    pub encrypted_state: SodiumCiphertext,
    roster_idx: u32,
}

impl fmt::Debug for EnclaveKeyCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnclaveKeyCiphertext {{ encrypted_state: 0x{}, roster_idx: {:?} }}",
            hex::encode(self.encode()),
            self.roster_idx()
        )
    }
}

impl EnclaveKeyCiphertext {
    pub fn new(encrypted_state: SodiumCiphertext, roster_idx: u32) -> Self {
        EnclaveKeyCiphertext {
            encrypted_state,
            roster_idx,
        }
    }

    pub fn decode(bytes: &[u8]) -> crate::localstd::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(bytes)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encrypted_state.encode()
    }

    pub fn encrypted_state(&self) -> &SodiumCiphertext {
        &self.encrypted_state
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }
}
