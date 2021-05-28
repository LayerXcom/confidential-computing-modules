//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use frame_host::engine::*;

/// State function of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct EncIntegerAvgStateFuncWorkflow;

// impl HostEngine for EncIntegerAvgStateFuncWorkflow {
//     type HI = HostEncAvgState;
//     type EI = EnclaveEncAvgState;
//     type EO = EnclaveEncAvgState;
//     type HO = HostEncAvgState;
//     const ECALL_MAX_SIZE: usize = 1024;
// }
