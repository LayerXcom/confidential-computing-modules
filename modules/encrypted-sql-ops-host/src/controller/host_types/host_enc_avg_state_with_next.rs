//! Output to host.

use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::{enc_aggregate_state::EncAvgState, EncInteger},
    enclave_types::EnclaveEncAvgStateWithNext,
};

use super::HostOutputEncAvgState;

/// Encrypted average state.
#[derive(Clone, Debug)]
pub struct HostEncAvgStateWithNext {
    state: EncAvgState,
    next: EncInteger,
}

impl HostInput for HostEncAvgStateWithNext {
    type EnclaveInput = EnclaveEncAvgStateWithNext;
    type HostOutput = HostOutputEncAvgState;

    fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
        Ok((
            EnclaveEncAvgStateWithNext::new(self.state, self.next),
            HostOutputEncAvgState(None),
        ))
    }
}

impl HostEncAvgStateWithNext {
    /// Constructor
    pub fn new(state: EncAvgState, next: EncInteger, ecall_cmd: u32) -> Self {
        Self { state, next }
    }
}
