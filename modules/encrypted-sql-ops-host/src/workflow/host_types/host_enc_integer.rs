//! Output to host.

use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::EncInteger, enclave_types::EnclaveEncInteger,
};

/// FIXME: since HostInput::apply() returns HostOutput (without ecall),
/// HostOutput first should be None, and then Some() after ecall.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct HostEncInteger(pub(super) Option<EncInteger>);

impl HostOutput for HostEncInteger {
    type EcallOutput = EnclaveEncInteger;

    fn set_ecall_output(self, output: Self::EcallOutput) -> anyhow::Result<Self> {
        Ok(Self::from(output))
    }
}

impl From<HostEncInteger> for EncInteger {
    fn from(w: HostEncInteger) -> Self {
        w.0.expect("From<HostEncInteger> for EncInteger must be called after HostEngine::exec()")
    }
}

impl From<EnclaveEncInteger> for HostEncInteger {
    fn from(e: EnclaveEncInteger) -> Self {
        let ei = e.into_encinteger();
        Self(Some(ei))
    }
}
