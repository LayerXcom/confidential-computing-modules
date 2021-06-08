use crate::aggregate_calc::AggregateCalc;
use crate::plain_types::PlainAvgState;
use crate::type_crypt::Pad16BytesDecrypt;
use frame_enclave::BasicEnclaveUseCase;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::ecall_cmd::ENCINTEGER_AVG_STATE_FUNC;
use module_encrypted_sql_ops_ecall_types::enclave_types::{
    EnclaveEncAvgState, EnclaveEncAvgStateWithNext,
};

/// EncIntegerAvgStateFunc command running inside enclave.
#[derive(Clone, Debug)]
pub struct EncIntegerAvgStateFuncUseCase<'c, C> {
    enclave_input: EnclaveEncAvgStateWithNext,
    enclave_context: &'c C,
}

impl<'c, C> BasicEnclaveUseCase<'c, C> for EncIntegerAvgStateFuncUseCase<'c, C>
where
    C: ConfigGetter,
{
    type EI = EnclaveEncAvgStateWithNext;
    type EO = EnclaveEncAvgState;
    const ENCLAVE_USE_CASE_ID: u32 = ENCINTEGER_AVG_STATE_FUNC;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self {
            enclave_input,
            enclave_context,
        })
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        let (enc_current_state, enc_next) = self.enclave_input.into_inner();

        let mut plain_current_state = PlainAvgState::from_encrypted(enc_current_state)?;
        let plain_next = enc_next.decrypt()?;

        plain_current_state.accumulate(plain_next.to_i32());

        let enc_next_state = plain_current_state.into_encrypted();
        Ok(EnclaveEncAvgState::from(enc_next_state))
    }
}
