use anonify_io_types::*;
use anyhow::{anyhow, Result};
use codec::{Decode, Encode};
use frame_common::{crypto::{Sha256, BackupPathSecret}, state_types::StateType};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_treekem::handshake::HandshakeParams;
use frame_mra_tls::{Client, ClientConfig};
use remote_attestation::RAService;

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
        let quote = enclave_context.quote()?;
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let (report, report_sig) = RAService::remote_attestation(ias_url, sub_key, &quote)?;
        let mrenclave_ver = enclave_context.mrenclave_ver();
        let group_key = &*enclave_context.read_group_key();
        let (handshake, path_secret, epoch) = group_key.create_handshake()?;
        let export_path_secret =
            path_secret.clone().try_into_exporting(epoch, handshake.hash().as_ref())?;
        let export_handshake = handshake.into_export();

        if enclave_context.is_backup_enabled() {
            let backup_path_secret = BackupPathSecret::new(path_secret.as_bytes().to_vec(), epoch);
            let mut client_config = ClientConfig::default();
            let ca_certificate = enclave_context.ca_certificate();
            let mra_tls_server_address = enclave_context.server_address();
            client_config.add_pem_to_root(ca_certificate)?;

            let mut mra_tls_client = Client::new(mra_tls_server_address, client_config)?;
            let _resp: serde_json::Value = mra_tls_client.send_json(backup_path_secret)?;
        }

        Ok(output::ReturnJoinGroup::new(
            report.into_vec(),
            report_sig.into_vec(),
            export_handshake.encode(),
            mrenclave_ver,
            export_handshake.roster_idx(),
            export_path_secret,
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
        let (handshake, path_secret, epoch) = group_key.create_handshake()?;
        let export_path_secret =
            path_secret.try_into_exporting(epoch, handshake.hash().as_ref())?;
        let export_handshake = handshake.into_export();
        let roster_idx = export_handshake.roster_idx();
        let msg = Sha256::hash_with_u32(&export_handshake.encode(), roster_idx);
        let sig = enclave_context.sign(msg.as_bytes())?;
        let enclave_sig = sig.0;
        let recovery_id = sig.1;

        Ok(output::ReturnHandshake::new(
            export_handshake,
            export_path_secret,
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

        group_key.process_handshake(&handshake)?;

        Ok(output::Empty::default())
    }
}
