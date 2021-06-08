use frame_common::{EnclaveInput, EnclaveOutput};

use crate::{
    enc_type::enc_aggregate_state::EncAvgState,
    serde::{Deserialize, Serialize},
};

/// Intermediate state to calculate average (encrypted).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EnclaveEncAvgState(EncAvgState);

impl EnclaveInput for EnclaveEncAvgState {}
impl EnclaveOutput for EnclaveEncAvgState {}

impl From<EncAvgState> for EnclaveEncAvgState {
    fn from(e: EncAvgState) -> Self {
        Self(e)
    }
}

impl EnclaveEncAvgState {
    /// Get inner representation
    pub fn into_enc_avg_state(self) -> EncAvgState {
        self.0
    }
}
