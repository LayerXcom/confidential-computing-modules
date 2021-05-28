//! Output to host.

use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::EncInteger, enclave_types::EncIntegerWrapper as EnclaveEncIntegerWrapper,
};

/// FIXME: since HostInput::apply() returns HostOutput (without ecall),
/// HostOutput first should be None, and then Some() after ecall.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct EncIntegerWrapper(pub(super) Option<EncInteger>);

impl HostOutput for EncIntegerWrapper {
    type EcallOutput = EnclaveEncIntegerWrapper;

    fn set_ecall_output(self, output: Self::EcallOutput) -> anyhow::Result<Self> {
        Ok(Self::from(output))
    }
}

impl From<EncIntegerWrapper> for EncInteger {
    fn from(w: EncIntegerWrapper) -> Self {
        w.0.expect("From<EncIntegerWrapper> for EncInteger must be called after HostEngine::exec()")
    }
}

impl From<EnclaveEncIntegerWrapper> for EncIntegerWrapper {
    fn from(e: EnclaveEncIntegerWrapper) -> Self {
        let ei = e.into_encinteger();
        Self(Some(ei))
    }
}
