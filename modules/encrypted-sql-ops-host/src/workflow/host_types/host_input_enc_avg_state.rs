//! Output to host.

use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

use super::HostPlainReal;

/// Encrypted average state.
///
/// FIXME: merge with HostOutputEncAvgState
#[derive(Clone, Debug)]
pub struct HostInputEncAvgState {
    enc_avg_state: EncAvgState,
    ecall_cmd: u32,
}

impl HostInput for HostInputEncAvgState {
    type EcallInput = EnclaveEncAvgState;
    type HostOutput = HostPlainReal;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((
            EnclaveEncAvgState::from(self.enc_avg_state),
            HostPlainReal::from(f32::NAN),
        ))
    }

    fn ecall_cmd(&self) -> u32 {
        self.ecall_cmd
    }
}

impl HostInputEncAvgState {
    /// Constructor
    pub fn new(enc_avg_state: EncAvgState, ecall_cmd: u32) -> Self {
        Self {
            enc_avg_state,
            ecall_cmd,
        }
    }
}
