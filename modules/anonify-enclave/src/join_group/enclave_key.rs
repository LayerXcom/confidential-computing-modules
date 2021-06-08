use anonify_ecall_types::cmd::JOIN_GROUP_ENCLAVE_KEY_CMD;
use anonify_ecall_types::*;
use anyhow::Result;
use frame_common::state_types::StateType;
use frame_enclave::StateRuntimeEnclaveUseCase;
use frame_runtime::traits::*;

/// A add handshake Sender
#[derive(Debug, Clone)]
pub struct JoinGroupWithEnclaveKey<'c, C> {
    enclave_context: &'c C,
}

impl<'c, C> StateRuntimeEnclaveUseCase<'c, C> for JoinGroupWithEnclaveKey<'c, C>
where
    C: ContextOps<S = StateType> + Clone,
{
    type EI = input::Empty;
    type EO = output::ReturnJoinGroup;
    const ENCLAVE_USE_CASE_ID: u32 = JOIN_GROUP_ENCLAVE_KEY_CMD;

    fn new(_enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run(self) -> Result<Self::EO> {
        let attested_report = self.enclave_context.quote()?.remote_attestation(
            self.enclave_context.ias_url(),
            self.enclave_context.sub_key(),
            self.enclave_context.ias_root_cert().to_vec(),
        )?;

        Ok(output::ReturnJoinGroup::new(
            attested_report.report().to_vec(),
            attested_report.report_sig().to_vec(),
            None,
            self.enclave_context.mrenclave_ver(),
            self.enclave_context.my_roster_idx() as u32,
        ))
    }
}
