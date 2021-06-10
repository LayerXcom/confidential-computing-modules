use crate::{
    enc_type::EncInteger,
    serde::{Deserialize, Serialize},
};
use frame_common::EnclaveOutput;

/// Encrypted INTEGER.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclaveEncInteger(EncInteger);

impl EnclaveOutput for EnclaveEncInteger {}

impl From<EncInteger> for EnclaveEncInteger {
    fn from(e: EncInteger) -> Self {
        Self(e)
    }
}

impl EnclaveEncInteger {
    /// Get inner representation
    pub fn into_encinteger(self) -> EncInteger {
        self.0
    }
}
