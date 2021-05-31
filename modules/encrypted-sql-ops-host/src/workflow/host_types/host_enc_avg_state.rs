//! Output to host.

use frame_host::engine::{HostInput, HostOutput};
use module_encrypted_sql_ops_ecall_types::{
    enc_type::enc_aggregate_state::EncAvgState, enclave_types::EnclaveEncAvgState,
};

/// Encrypted average state.
///
/// FIXME: HostInputEncAvgState & HostOutputEncAvgState should be integrated into one type.
/// Input has weird `ecall_cmd` and output has `Option` internally to be handled with HostInput::apply.
#[derive(Clone, Debug)]
pub struct HostInputEncAvgState {
    inner: EncAvgState,
    ecall_cmd: u32,
}

impl HostInput for HostInputEncAvgState {
    type EcallInput = EnclaveEncAvgState;
    type HostOutput = HostOutputEncAvgState;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((
            EnclaveEncAvgState::from(self.inner),
            HostOutputEncAvgState(None),
        ))
    }

    fn ecall_cmd(&self) -> u32 {
        self.ecall_cmd
    }
}

impl HostInputEncAvgState {
    /// Constructor
    pub fn new(inner: EncAvgState, ecall_cmd: u32) -> Self {
        Self { inner, ecall_cmd }
    }
}

/// Encrypted average state.
#[derive(Clone, Debug, Default)]
pub struct HostOutputEncAvgState(Option<EncAvgState>);

impl HostOutput for HostOutputEncAvgState {
    type EcallOutput = EnclaveEncAvgState;

    fn set_ecall_output(self, output: Self::EcallOutput) -> anyhow::Result<Self> {
        Ok(Self::from(output))
    }
}

impl From<HostOutputEncAvgState> for EncAvgState {
    fn from(w: HostOutputEncAvgState) -> Self {
        w.0.expect(
            "From<HostInputEncAvgState> for EncAvgState must be called after HostEngine::exec()",
        )
    }
}

impl From<EnclaveEncAvgState> for HostOutputEncAvgState {
    fn from(e: EnclaveEncAvgState) -> Self {
        let eas = e.into_enc_avg_state();
        Self(Some(eas))
    }
}
