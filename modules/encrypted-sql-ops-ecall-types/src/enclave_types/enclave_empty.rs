use crate::serde::{Deserialize, Serialize};
use frame_common::EcallInput;

/// Empty input for HostEngine & EnclaveEngine.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclaveEmpty;

impl EcallInput for EnclaveEmpty {}

impl Default for EnclaveEmpty {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine::EI")
    }
}
