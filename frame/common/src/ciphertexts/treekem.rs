use crate::bincode;
use crate::localstd::{boxed::Box, cmp::Ordering, fmt, vec::Vec};
use crate::serde::{Deserialize, Serialize};
use crate::serde_bytes;

/// Application message broadcasted to other members.
#[derive(Clone, Serialize, Deserialize, Eq, Ord, Hash, Default)]
#[serde(crate = "crate::serde")]
pub struct TreeKemCiphertext {
    generation: u32,
    epoch: u32,
    roster_idx: u32,
    #[serde(with = "serde_bytes")]
    encrypted_state: Vec<u8>,
}

impl fmt::Debug for TreeKemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TreeKemCiphertext {{ generation: {:?}, epoch: {:?}, roster_idx: {:?}, encrypted_state: 0x{} }}",
            self.generation(),
            self.epoch(),
            self.roster_idx(),
            hex::encode(&self.encrypted_state)
        )
    }
}

impl PartialEq for TreeKemCiphertext {
    fn eq(&self, other: &TreeKemCiphertext) -> bool {
        self.roster_idx() == other.roster_idx()
            && self.generation() == other.generation()
            && self.epoch() == other.epoch()
    }
}

/// Ordering by priority of roster_idx, epoch, generation
impl PartialOrd for TreeKemCiphertext {
    fn partial_cmp(&self, other: &TreeKemCiphertext) -> Option<Ordering> {
        let roster_idx_ord = self.roster_idx().partial_cmp(&other.roster_idx())?;
        if roster_idx_ord != Ordering::Equal {
            return Some(roster_idx_ord);
        }

        let epoch_ord = self.epoch().partial_cmp(&other.epoch())?;
        if epoch_ord != Ordering::Equal {
            return Some(epoch_ord);
        }

        let gen_ord = self.generation().partial_cmp(&other.generation())?;
        if gen_ord != Ordering::Equal {
            return Some(gen_ord);
        }

        Some(Ordering::Equal)
    }
}

impl TreeKemCiphertext {
    pub fn new(generation: u32, epoch: u32, roster_idx: u32, encrypted_state: Vec<u8>) -> Self {
        TreeKemCiphertext {
            generation,
            epoch,
            roster_idx,
            encrypted_state,
        }
    }

    pub fn decode(bytes: &[u8]) -> crate::localstd::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(&bytes[..])
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn encrypted_state_ref(&self) -> &[u8] {
        &self.encrypted_state
    }
}
