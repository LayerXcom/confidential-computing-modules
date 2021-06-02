//! Output to host.

use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::{enc_aggregate_state::EncAvgState, EncInteger},
    enclave_types::EnclaveEncAvgStateWithNext,
};

use super::HostEncAvgState;

/// Encrypted average state.
#[derive(Clone, Debug)]
pub struct HostEncAvgStateWithNext {
    state: EncAvgState,
    next: EncInteger,
    ecall_cmd: u32,
}

impl HostInput for HostEncAvgStateWithNext {
    type EcallInput = EnclaveEncAvgStateWithNext;
    type HostOutput = HostEncAvgState;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((
            EnclaveEncAvgStateWithNext::new(self.state, self.next),
            HostEncAvgState(None),
        ))
    }

    fn ecall_cmd(&self) -> u32 {
        self.ecall_cmd
    }
}

impl HostEncAvgStateWithNext {
    /// Constructor
    pub fn new(state: EncAvgState, next: EncInteger, ecall_cmd: u32) -> Self {
        Self {
            state,
            next,
            ecall_cmd,
        }
    }
}
