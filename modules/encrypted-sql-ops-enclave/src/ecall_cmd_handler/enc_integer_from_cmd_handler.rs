use crate::type_crypt::encinteger::EncIntegerEncrypt;
use frame_enclave::BasicEnclaveEngine;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::{
    enc_type::EncInteger,
    enclave_types::{EncIntegerWrapper, RawInteger},
};

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

    fn handle<C>(self, enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        let encinteger = EncInteger::encrypt(self.enclave_input.to_i32());
        Ok(EncIntegerWrapper::from(encinteger))
    }
}

impl Default for EncIntegerFromCmdHandler {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine")
    }
}
