//! Output to host.

use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

/// Encrypted average state.
#[derive(Clone, Debug, Default)]
pub struct HostEncAvgState(pub(super) Option<EncAvgState>);

impl HostOutput for HostEncAvgState {
    type EcallOutput = EnclaveEncAvgState;

    fn set_ecall_output(self, output: Self::EcallOutput) -> anyhow::Result<Self> {
        Ok(Self::from(output))
    }
}

impl From<HostEncAvgState> for EncAvgState {
    fn from(w: HostEncAvgState) -> Self {
        w.0.expect(
            "From<HostInputEncAvgState> for EncAvgState must be called after HostEngine::exec()",
        )
    }
}

impl From<EnclaveEncAvgState> for HostEncAvgState {
    fn from(e: EnclaveEncAvgState) -> Self {
        let eas = e.into_enc_avg_state();
        Self(Some(eas))
    }
}
