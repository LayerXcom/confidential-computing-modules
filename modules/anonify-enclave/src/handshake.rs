use anonify_config::IAS_ROOT_CERT;
use anonify_io_types::*;
use anyhow::{anyhow, Result};
use codec::{Decode, Encode};
use frame_common::{
    crypto::{BackupPathSecret, Sha256},
    state_types::StateType,
};
use frame_enclave::EnclaveEngine;
use frame_mra_tls::{AttestedTlsConfig, Client, ClientConfig};
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
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let spid = enclave_context.spid();
        let attested_report = enclave_context.quote()?.remote_attestation(
            ias_url,
            sub_key,
            IAS_ROOT_CERT.to_vec(),
        )?;

        let mrenclave_ver = enclave_context.mrenclave_ver();
        let group_key = &*enclave_context.read_group_key();
        let (handshake, path_secret) = group_key.create_handshake()?;
        let epoch = handshake.prior_epoch();
        let export_path_secret = path_secret
            .clone()
            .try_into_exporting(epoch, handshake.hash().as_ref())?;
        let export_handshake = handshake.into_export();

        if enclave_context.is_backup_enabled() {
            let backup_path_secret = BackupPathSecret::new(path_secret.as_bytes().to_vec(), epoch);

            let attested_tls_config =
                AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec())?;

            let client_config = ClientConfig::from_attested_tls_config(attested_tls_config)?
                .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec());
            let mra_tls_server_address = enclave_context.server_address();
            let mut mra_tls_client = Client::new(mra_tls_server_address, client_config).unwrap();
            let _resp: serde_json::Value = mra_tls_client.send_json(backup_path_secret)?;
        }

        Ok(output::ReturnJoinGroup::new(
            attested_report.report().to_vec(),
            attested_report.report_sig().to_vec(),
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
        let (handshake, path_secret) = group_key.create_handshake()?;
        let epoch = handshake.prior_epoch();
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
