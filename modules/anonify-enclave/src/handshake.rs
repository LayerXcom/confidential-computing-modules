use anonify_io_types::*;
use anyhow::{anyhow, Result};
use codec::{Decode, Encode};
use frame_common::{crypto::Sha256, state_types::StateType};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_treekem::handshake::HandshakeParams;
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
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let (report, report_sig) = enclave_context.quote()?
            .remote_attestation(ias_url, sub_key)?;

        let mrenclave_ver = enclave_context.mrenclave_ver();
        let group_key = &*enclave_context.read_group_key();
        let (export_handshake, export_path_secret) = group_key.create_handshake()?;

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
        let (export_handshake, export_path_secret) = group_key.create_handshake()?;
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
