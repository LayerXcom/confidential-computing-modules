use anonify_ecall_types::*;
use anyhow::Result;
use frame_common::state_types::StateType;
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;

/// A add handshake Sender
#[derive(Debug, Clone, Default)]
pub struct JoinGroupWithEnclaveKey;

impl EnclaveEngine for JoinGroupWithEnclaveKey {
    type EI = input::Empty;
    type EO = output::ReturnJoinGroup;

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let attested_report = enclave_context.quote()?.remote_attestation(
            enclave_context.ias_url(),
            enclave_context.sub_key(),
            enclave_context.ias_root_cert().to_vec(),
        )?;

        Ok(output::ReturnJoinGroup::new(
            attested_report.report().to_vec(),
            attested_report.report_sig().to_vec(),
            None,
            enclave_context.mrenclave_ver(),
            enclave_context.my_roster_idx() as u32,
        ))
    }
}
