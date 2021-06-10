use frame_common::EnclaveInput;

use crate::{
    enc_type::{enc_aggregate_state::EncAvgState, EncInteger},
    serde::{Deserialize, Serialize},
};

/// Intermediate state to calculate average (encrypted).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclaveEncAvgStateWithNext {
    state: EncAvgState,
    next: EncInteger,
}

impl EnclaveInput for EnclaveEncAvgStateWithNext {}

impl EnclaveEncAvgStateWithNext {
    /// Constructor
    pub fn new(state: EncAvgState, next: EncInteger) -> Self {
        Self { state, next }
    }

    /// Get raw representation
    pub fn into_inner(self) -> (EncAvgState, EncInteger) {
        (self.state, self.next)
    }
}
