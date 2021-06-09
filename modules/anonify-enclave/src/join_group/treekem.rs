use anonify_ecall_types::cmd::JOIN_GROUP_TREEKEM_CMD;
use anonify_ecall_types::*;
use anyhow::Result;
use frame_enclave::StateRuntimeEnclaveUseCase;
#[cfg(feature = "backup-enable")]
use frame_mra_tls::key_vault::request::BackupPathSecretRequestBody;
use frame_runtime::traits::*;

use crate::context::AnonifyEnclaveContext;

/// Joining the group with treekem-based handshake
#[derive(Debug, Clone)]
pub struct JoinGroupWithTreeKem<'c> {
    enclave_context: &'c AnonifyEnclaveContext,
}

impl<'c> StateRuntimeEnclaveUseCase<'c, AnonifyEnclaveContext> for JoinGroupWithTreeKem<'c> {
    type EI = input::Empty;
    type EO = output::ReturnJoinGroup;
    const ENCLAVE_USE_CASE_ID: u32 = JOIN_GROUP_TREEKEM_CMD;

    fn new(
        _enclave_input: Self::EI,
        enclave_context: &'c AnonifyEnclaveContext,
    ) -> anyhow::Result<Self> {
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

        let (handshake, path_secret) =
            (&*self.enclave_context.read_group_key()).create_handshake()?;
        let epoch = handshake.prior_epoch();
        let id = handshake.hash();
        let export_path_secret = path_secret.clone().try_into_exporting(epoch, id.as_ref())?;
        self.enclave_context
            .store_path_secrets()
            .save_to_local_filesystem(&export_path_secret)?;
        let export_handshake = handshake.clone().into_export();

        #[cfg(feature = "backup-enable")]
        {
            let backup_path_secret = BackupPathSecretRequestBody::new(
                path_secret.as_bytes().to_vec(),
                epoch,
                handshake.roster_idx(),
                id.as_ref().to_vec(),
            );
            self.enclave_context
                .backup_path_secret(backup_path_secret)?;
        }

        Ok(output::ReturnJoinGroup::new(
            attested_report.report().to_vec(),
            attested_report.report_sig().to_vec(),
            Some(export_handshake.encode()),
            self.enclave_context.mrenclave_ver(),
            export_handshake.roster_idx(),
        ))
    }
}
