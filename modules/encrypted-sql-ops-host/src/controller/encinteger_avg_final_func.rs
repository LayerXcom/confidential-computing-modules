//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use super::host_types::{HostInputEncAvgState, HostPlainReal};
use frame_host::ecall_controller::EcallController;
use module_encrypted_sql_ops_ecall_types::enclave_types::{EnclaveEncAvgState, EnclavePlainReal};

/// Finalize function of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct EncIntegerAvgFinalFuncController;

impl EcallController for EncIntegerAvgFinalFuncController {
    type HI = HostInputEncAvgState;
    type EI = EnclaveEncAvgState;
    type EO = EnclavePlainReal;
    type HO = HostPlainReal;
    const EI_MAX_SIZE: usize = 256;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(EnclaveEncAvgState::from(host_input.enc_avg_state))
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(enclave_output.to_f32().into())
    }
}
