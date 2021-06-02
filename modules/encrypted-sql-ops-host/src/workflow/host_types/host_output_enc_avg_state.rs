//! Output to host.

use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

/// Encrypted average state.
#[derive(Clone, Debug, Default)]
pub struct HostOutputEncAvgState(pub(super) Option<EncAvgState>);

impl HostOutput for HostOutputEncAvgState {
    type EcallOutput = EnclaveEncAvgState;

    fn set_ecall_output(self, output: Self::EcallOutput) -> anyhow::Result<Self> {
        Ok(Self(Some(output.into_enc_avg_state())))
    }
}

impl From<HostOutputEncAvgState> for EncAvgState {
    fn from(h: HostOutputEncAvgState) -> Self {
        h.0.expect(
            "From<HostInputEncAvgState> for EncAvgState must be called after HostEngine::exec()",
        )
    }
}
