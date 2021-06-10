use crate::{
    enclave_context::EncryptedSqlOpsEnclaveContext, plain_types::PlainInteger,
    type_crypt::Pad16BytesEncrypt,
};
use frame_enclave::BasicEnclaveUseCase;
use module_encrypted_sql_ops_ecall_types::{
    ecall_cmd::ENCINTEGER_FROM,
    enclave_types::{EnclaveEncInteger, EnclavePlainInteger},
};

/// EncIntegerFrom command running inside enclave.
#[derive(Clone, Debug)]
pub struct EncIntegerFromUseCase<'c> {
    enclave_input: EnclavePlainInteger,
    enclave_context: &'c EncryptedSqlOpsEnclaveContext,
}

impl<'c> BasicEnclaveUseCase<'c, EncryptedSqlOpsEnclaveContext> for EncIntegerFromUseCase<'c> {
    type EI = EnclavePlainInteger;
    type EO = EnclaveEncInteger;
    const ENCLAVE_USE_CASE_ID: u32 = ENCINTEGER_FROM;

    fn new(
        enclave_input: Self::EI,
        enclave_context: &'c EncryptedSqlOpsEnclaveContext,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            enclave_input,
            enclave_context,
        })
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        let plain_i32 = PlainInteger::from(self.enclave_input);
        let encinteger = plain_i32.encrypt();
        Ok(EnclaveEncInteger::from(encinteger))
    }
}
