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
}

impl From<EncIntegerWrapper> for EncInteger {
    fn from(w: EncIntegerWrapper) -> Self {
        w.0.expect("From<EncIntegerWrapper> for EncInteger must be called after HostEngine::exec()")
    }
}
