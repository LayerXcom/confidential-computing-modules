use anonify_io_types::*;
use anyhow::{anyhow, Result};
use codec::{Decode, Encode};
#[cfg(feature = "backup-enable")]
use frame_common::crypto::BackupPathSecret;
use frame_common::{crypto::Sha256, state_types::StateType};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_treekem::handshake::HandshakeParams;

/// A add handshake Sender
#[derive(Debug, Clone)]
pub struct JoinGroupSender;

impl EnclaveEngine for JoinGroupSender {
    type EI = input::CallJoinGroup;
    type EO = output::ReturnJoinGroup;

    fn handle<R, C>(
        _ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> Result<Self::EO>
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
            let backup_path_secret = BackupPathSecret::new(
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
            export_handshake.encode(),
            enclave_context.mrenclave_ver(),
            export_handshake.roster_idx(),
        ))
    }
}

/// A update handshake sender
#[derive(Debug, Clone)]
pub struct HandshakeSender;

impl EnclaveEngine for HandshakeSender {
    type EI = input::CallHandshake;
    type EO = output::ReturnHandshake;

    fn handle<R, C>(
        _ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let group_key = &*enclave_context.read_group_key();
        let (handshake, path_secret) = group_key.create_handshake()?;
        let epoch = handshake.prior_epoch();
        let id = handshake.hash();
        let export_path_secret = path_secret.clone().try_into_exporting(epoch, id.as_ref())?;
        enclave_context
            .store_path_secrets()
            .save_to_local_filesystem(&export_path_secret)?;
        let export_handshake = handshake.clone().into_export();

        #[cfg(feature = "backup-enable")]
        {
            let backup_path_secret = BackupPathSecret::new(
                path_secret.as_bytes().to_vec(),
                epoch,
                handshake.roster_idx(),
                id.as_ref().to_vec(),
            );
            enclave_context.backup_path_secret(backup_path_secret)?;
        }

        let roster_idx = export_handshake.roster_idx();
        let msg = Sha256::hash_with_u32(&export_handshake.encode(), roster_idx);
        let sig = enclave_context.sign(msg.as_bytes())?;
        let enclave_sig = sig.0;
        let recovery_id = sig.1;

        Ok(output::ReturnHandshake::new(
            export_handshake,
            enclave_sig,
            recovery_id,
            roster_idx,
        ))
    }
}

/// A handshake receiver
#[derive(Debug, Clone)]
pub struct HandshakeReceiver;

impl EnclaveEngine for HandshakeReceiver {
    type EI = input::InsertHandshake;
    type EO = output::Empty;

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let handshake = HandshakeParams::decode(&mut &ecall_input.handshake().handshake()[..])
            .map_err(|_| anyhow!("HandshakeParams::decode Error"))?;

        group_key.process_handshake(
            enclave_context.store_path_secrets(),
            &handshake,
            |ps_id, roster_idx| C::recover_path_secret(enclave_context, ps_id, roster_idx),
        )?;

        Ok(output::Empty::default())
    }
}
