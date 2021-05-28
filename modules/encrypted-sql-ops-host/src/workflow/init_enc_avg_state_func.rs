//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use frame_host::engine::*;
use module_encrypted_sql_ops_ecall_types::enclave_types::{EnclaveEmpty, EnclaveEncAvgState};

use super::host_types::{HostEmpty, HostOutputEncAvgState};

/// Initial state of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct InitEncAvgStateFuncWorkflow;

impl HostEngine for InitEncAvgStateFuncWorkflow {
    type HI = HostEmpty<HostOutputEncAvgState>;
    type EI = EnclaveEmpty;
    type EO = EnclaveEncAvgState;
    type HO = HostOutputEncAvgState;
    const ECALL_MAX_SIZE: usize = 1024;
}
