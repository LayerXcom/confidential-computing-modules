//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use super::host_types::{HostInputEncAvgState, HostPlainReal};
use frame_host::engine::*;
use module_encrypted_sql_ops_ecall_types::enclave_types::{EnclaveEncAvgState, EnclavePlainReal};

/// Finalize function of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct EncIntegerAvgFinalFuncWorkflow;

impl HostEngine for EncIntegerAvgFinalFuncWorkflow {
    type HI = HostInputEncAvgState;
    type EI = EnclaveEncAvgState;
    type EO = EnclavePlainReal;
    type HO = HostPlainReal;
    const ECALL_MAX_SIZE: usize = 256;
}
