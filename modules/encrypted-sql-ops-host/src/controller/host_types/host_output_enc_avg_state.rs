//! Output to host.

use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

/// Encrypted average state.
#[derive(Clone, Debug, Default)]
pub struct HostOutputEncAvgState(EncAvgState);

impl HostOutput for HostOutputEncAvgState {}

impl From<HostOutputEncAvgState> for EncAvgState {
    fn from(h: HostOutputEncAvgState) -> Self {
        h.0
    }
}
