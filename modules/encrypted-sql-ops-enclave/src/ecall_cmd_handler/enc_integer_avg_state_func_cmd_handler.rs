use crate::aggregate_calc::AggregateCalc;
use crate::plain_types::PlainAvgState;
use crate::type_crypt::Pad16BytesDecrypt;
use frame_enclave::BasicEnclaveEngine;
use frame_runtime::ConfigGetter;
use module_encrypted_sql_ops_ecall_types::enclave_types::{
    EnclaveEncAvgState, EnclaveEncAvgStateWithNext,
};

/// EncIntegerAvgStateFunc command running inside enclave.
#[derive(Clone, Debug)]
pub struct EncIntegerAvgStateFuncCmdHandler {
    enclave_input: EnclaveEncAvgStateWithNext,
}

impl BasicEnclaveEngine for EncIntegerAvgStateFuncCmdHandler {
    type EI = EnclaveEncAvgStateWithNext;
    type EO = EnclaveEncAvgState;

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
        let (enc_current_state, enc_next) = self.enclave_input.into_inner();

        let mut plain_current_state = PlainAvgState::from_encrypted(enc_current_state)?;
        let plain_next = enc_next.decrypt()?;

        plain_current_state.accumulate(plain_next.to_i32());

        let enc_next_state = plain_current_state.to_encrypted();
        Ok(EnclaveEncAvgState::from(enc_next_state))
    }
}

impl Default for EncIntegerAvgStateFuncCmdHandler {
    fn default() -> Self {
        unreachable!("FIXME stop requiring Default for *EnclaveEngine")
    }
}
