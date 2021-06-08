//! Output to host.

use frame_host::ecall_controller::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

/// Encrypted average state.
#[derive(Clone, Debug)]
pub struct HostOutputEncAvgState(EncAvgState);

impl HostOutput for HostOutputEncAvgState {}

impl From<HostOutputEncAvgState> for EncAvgState {
    fn from(h: HostOutputEncAvgState) -> Self {
        h.0
    }
}

impl From<EncAvgState> for HostOutputEncAvgState {
    fn from(e: EncAvgState) -> Self {
        Self(e)
    }
}

impl From<EnclaveEncAvgState> for HostOutputEncAvgState {
    fn from(e: EnclaveEncAvgState) -> Self {
        Self::from(e.into_enc_avg_state())
    }
}
