use crate::{
    enc_type::EncInteger,
    serde::{Deserialize, Serialize},
};
use frame_common::EcallOutput;

/// Output from enclave
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclaveEncInteger(EncInteger);

impl EcallOutput for EnclaveEncInteger {}

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

impl Default for EnclaveEncInteger {
    fn default() -> Self {
        unreachable!(
            "FIXME stop requiring Default for *EnclaveEngine::EO (must be created via handle())"
        )
    }
}
