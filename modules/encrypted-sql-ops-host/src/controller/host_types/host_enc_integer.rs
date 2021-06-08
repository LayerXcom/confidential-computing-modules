//! Output to host.

use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::EncInteger, enclave_types::EnclaveEncInteger,
};

/// FIXME: since HostInput::apply() returns HostOutput (without ecall),
/// HostOutput first should be None, and then Some() after ecall.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct HostEncInteger(pub(super) EncInteger);

impl HostOutput for HostEncInteger {}

impl From<HostEncInteger> for EncInteger {
    fn from(w: HostEncInteger) -> Self {
        w.0
    }
}

impl From<EnclaveEncInteger> for HostEncInteger {
    fn from(e: EnclaveEncInteger) -> Self {
        let ei = e.into_encinteger();
        Self(ei)
    }
}
