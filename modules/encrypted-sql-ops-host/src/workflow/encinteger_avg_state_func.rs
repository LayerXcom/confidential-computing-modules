//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use frame_host::engine::*;

/// State function of `AVG(ENCINTEGER)` custom aggregate.
#[derive(Debug)]
pub struct EncIntegerAvgStateFuncWorkflow;

// impl HostEngine for EncIntegerAvgStateFuncWorkflow {
//     type HI = HostPlainInteger;
//     type EI = PlainInteger;
//     type EO = EnclaveEncInteger;
//     type HO = host_output::EncIntegerWrapper;
//     const ECALL_MAX_SIZE: usize = 64;
// }
