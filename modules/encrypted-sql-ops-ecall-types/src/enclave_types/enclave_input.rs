use crate::serde::{Deserialize, Serialize};
use frame_common::EcallInput;

/// Input to enclave
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct RawInteger(i32);

impl EcallInput for RawInteger {}

impl From<i32> for RawInteger {
    fn from(integer: i32) -> Self {
        Self(integer)
    }
}

impl RawInteger {
    /// Gets raw representation
    pub fn to_i32(&self) -> i32 {
        self.0
    }
}

impl Default for RawInteger {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine::EI")
    }
}
