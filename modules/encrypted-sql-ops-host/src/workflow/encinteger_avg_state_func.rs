//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use super::host_types::{
    HostEncInteger, HostInputEncAvgState, HostOutputEncAvgState, HostPlainInteger,
};
use frame_host::engine::*;
use module_encrypted_sql_ops_ecall_types::enclave_types::{
    EnclaveEncAvgState, EnclaveEncInteger, EnclavePlainInteger,
};

/// State function of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct EncIntegerAvgStateFuncWorkflow;

impl HostEngine for EncIntegerAvgStateFuncWorkflow {
    type HI = HostInputEncAvgState;
    type EI = EnclaveEncAvgState;
    type EO = EnclaveEncAvgState;
    type HO = HostOutputEncAvgState;
    const ECALL_MAX_SIZE: usize = 64;
}
