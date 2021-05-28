use crate::{
    enc_type::EncInteger,
    serde::{Deserialize, Serialize},
};
use frame_common::EcallOutput;

/// Output from enclave
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EncIntegerWrapper(EncInteger);

impl EcallOutput for EncIntegerWrapper {}

impl From<EncInteger> for EncIntegerWrapper {
    fn from(e: EncInteger) -> Self {
        Self(e)
    }
}

impl EncIntegerWrapper {
    /// Get inner representation
    pub fn into_encinteger(self) -> EncInteger {
        self.0
    }
}

impl Default for EncIntegerWrapper {
    fn default() -> Self {
        unreachable!(
            "FIXME stop requiring Default for *EnclaveEngine::EO (must be created via handle())"
        )
    }
}
