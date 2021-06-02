use frame_enclave::BasicEnclaveEngine;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::{
    enclave_types::{EnclaveEncInteger, EnclavePlainInteger},
};

use crate::{plain_types::PlainInteger, type_crypt::Pad16BytesEncrypt};

/// EncIntegerFrom command running inside enclave.
#[derive(Clone, Hash, Debug)]
pub struct EncIntegerFromCmdHandler {
    enclave_input: EnclavePlainInteger,
}

impl BasicEnclaveEngine for EncIntegerFromCmdHandler {
    type EI = EnclavePlainInteger;
    type EO = EnclaveEncInteger;

    fn new<C>(ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ConfigGetter,
    {
        Ok(Self {
            enclave_input: ecall_input,
        })
    }

    fn handle<C>(self, _enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        let plain_i32 = PlainInteger::from(self.enclave_input);
        let encinteger = plain_i32.encrypt();
        Ok(EnclaveEncInteger::from(encinteger))
    }
}

impl Default for EncIntegerFromCmdHandler {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine")
    }
}
