use crate::aggregate_calc::AggregateCalc;
use crate::plain_types::PlainAvgState;
use frame_enclave::BasicEnclaveUseCase;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::ecall_cmd::ENCINTEGER_AVG_FINAL_FUNC;
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclaveEncAvgState;
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclavePlainReal;

/// EncIntegerAvgStateFunc command running inside enclave.
#[derive(Clone, Debug)]
pub struct EncIntegerAvgFinalFuncUseCase<'c, C> {
    enclave_input: EnclaveEncAvgState,
    enclave_context: &'c C,
}

impl<'c, C> BasicEnclaveUseCase<'c, C> for EncIntegerAvgFinalFuncUseCase<'c, C>
where
    C: ConfigGetter,
{
    type EI = EnclaveEncAvgState;
    type EO = EnclavePlainReal;
    const ENCLAVE_USE_CASE_ID: u32 = ENCINTEGER_AVG_FINAL_FUNC;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self {
            enclave_input,
            enclave_context,
        })
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        let enc_current_state = self.enclave_input.into_enc_avg_state();
        let plain_current_state = PlainAvgState::from_encrypted(enc_current_state)?;

        let avg = plain_current_state.finalize();
        Ok(EnclavePlainReal::from(avg))
    }
}
