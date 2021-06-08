//! Output to host.

use frame_host::ecall_controller::HostInput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

/// Encrypted average state.
///
/// FIXME: merge with HostOutputEncAvgState
#[derive(Clone, Debug)]
pub struct HostInputEncAvgState {
    enc_avg_state: EncAvgState,
}

impl HostInput for HostInputEncAvgState {}

impl HostInputEncAvgState {
    /// Constructor
    pub fn new(enc_avg_state: EncAvgState) -> Self {
        Self { enc_avg_state }
    }
}

impl From<HostInputEncAvgState> for EnclaveEncAvgState {
    fn from(h: HostInputEncAvgState) -> Self {
        Self::from(h.enc_avg_state)
    }
}
