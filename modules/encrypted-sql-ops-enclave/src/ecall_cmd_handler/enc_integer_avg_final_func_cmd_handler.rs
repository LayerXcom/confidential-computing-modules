use crate::aggregate_calc::AggregateCalc;
use crate::plain_types::PlainAvgState;
use frame_enclave::BasicEnclaveEngine;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclaveEncAvgState;
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclavePlainReal;

/// EncIntegerAvgStateFunc command running inside enclave.
#[derive(Clone, Debug)]
pub struct EncIntegerAvgFinalFuncCmdHandler {
    enclave_input: EnclaveEncAvgState,
}

impl BasicEnclaveEngine for EncIntegerAvgFinalFuncCmdHandler {
    type EI = EnclaveEncAvgState;
    type EO = EnclavePlainReal;

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
        let enc_current_state = self.enclave_input.into_enc_avg_state();
        let plain_current_state = PlainAvgState::from_encrypted(enc_current_state)?;

        let avg = plain_current_state.finalize();
        Ok(EnclavePlainReal::from(avg))
    }
}

impl Default for EncIntegerAvgFinalFuncCmdHandler {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine")
    }
}
