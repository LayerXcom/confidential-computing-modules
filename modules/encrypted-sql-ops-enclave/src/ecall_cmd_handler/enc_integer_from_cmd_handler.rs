use frame_enclave::BasicEnclaveEngine;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::enclave_types::{EncIntegerWrapper, RawInteger};

/// EncIntegerFrom command running inside enclave.
#[derive(Clone, Hash, Debug)]
pub struct EncIntegerFromCmdHandler {
    enclave_input: RawInteger,
}

impl BasicEnclaveEngine for EncIntegerFromCmdHandler {
    type EI = RawInteger;
    type EO = EncIntegerWrapper;

    fn new<C>(ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ConfigGetter,
    {
        Ok(Self {
            enclave_input: ecall_input,
        })
    }
}

impl Default for EncIntegerFromCmdHandler {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine")
    }
}
