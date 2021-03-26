use anonify_ecall_types::*;
use anyhow::{anyhow, Result};
use frame_common::{crypto::Sha256, state_types::StateType};
use frame_enclave::EnclaveEngine;
#[cfg(feature = "backup-enable")]
use frame_mra_tls::key_vault::request::BackupPathSecretRequestBody;
use frame_runtime::traits::*;
use frame_treekem::handshake::HandshakeParams;

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

        let (handshake, path_secret) = (&*enclave_context.read_group_key()).create_handshake()?;
        let epoch = handshake.prior_epoch();
        let id = handshake.hash();
        let export_path_secret = path_secret.clone().try_into_exporting(epoch, id.as_ref())?;
        enclave_context
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
            enclave_context.backup_path_secret(backup_path_secret)?;
        }

        Ok(output::ReturnJoinGroup::new(
            attested_report.report().to_vec(),
            attested_report.report_sig().to_vec(),
            Some(export_handshake.encode()),
            enclave_context.mrenclave_ver(),
            export_handshake.roster_idx(),
        ))
    }
}
