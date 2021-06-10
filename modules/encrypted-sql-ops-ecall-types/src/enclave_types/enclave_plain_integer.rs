use crate::serde::{Deserialize, Serialize};
use frame_common::EnclaveInput;

/// Plain-text INTEGER.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclavePlainInteger(i32);

impl EnclaveInput for EnclavePlainInteger {}

impl From<i32> for EnclavePlainInteger {
    fn from(integer: i32) -> Self {
        Self(integer)
    }
}

impl EnclavePlainInteger {
    /// Gets raw representation
    pub fn to_i32(&self) -> i32 {
        self.0
    }
}
