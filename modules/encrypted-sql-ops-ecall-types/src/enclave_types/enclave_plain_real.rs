use crate::serde::{Deserialize, Serialize};
use frame_common::EcallOutput;

/// Plain-text INTEGER.
#[derive(Copy, Clone, PartialEq, PartialOrd, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclavePlainReal(f32);

impl EcallOutput for EnclavePlainReal {}

impl From<f32> for EnclavePlainReal {
    fn from(f: f32) -> Self {
        Self(f)
    }
}

impl EnclavePlainReal {
    /// Gets raw representation
    pub fn to_f32(&self) -> f32 {
        self.0
    }
}

impl Default for EnclavePlainReal {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine::EI")
    }
}
