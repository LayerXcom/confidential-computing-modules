//! Output to host.

use frame_host::ecall_controller::HostInput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::{enc_aggregate_state::EncAvgState, EncInteger},
    enclave_types::EnclaveEncAvgStateWithNext,
};

/// Encrypted average state.
#[derive(Clone, Debug)]
pub struct HostEncAvgStateWithNext {
    state: EncAvgState,
    next: EncInteger,
}

impl HostInput for HostEncAvgStateWithNext {}

impl HostEncAvgStateWithNext {
    /// Constructor
    pub fn new(state: EncAvgState, next: EncInteger) -> Self {
        Self { state, next }
    }
}

impl From<HostEncAvgStateWithNext> for EnclaveEncAvgStateWithNext {
    fn from(h: HostEncAvgStateWithNext) -> Self {
        Self::new(h.state, h.next)
    }
}
