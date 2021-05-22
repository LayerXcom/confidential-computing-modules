use super::ecall_output;
use frame_host::engine::HostOutput;
use module_encrypted_sql_ops_ecall_types::EncInteger;

// FIXME: since HostInput::apply() returns HostOutput (without ecall),
// HostOutput first should be None, and then Some() after ecall.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
pub(super) struct EncIntegerWrapper(Option<EncInteger>);

impl HostOutput for EncIntegerWrapper {
    type EcallOutput = ecall_output::EncIntegerWrapper;
}
