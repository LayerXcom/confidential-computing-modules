use std::vec::Vec;
use anonify_types::{RawJoinGroupTx, RawInstructionTx, RawHandshakeTx, traits::RawEnclaveTx};
use anonify_common::{
    crypto::{UserAddress, Sha256, AccessRight, Ciphertext},
    traits::*,
    state_types::MemId,
};
use anonify_treekem::handshake::HandshakeParams;
use codec::Encode;
use remote_attestation::{RAService, AttestationReport, ReportSig};
use crate::{
    error::Result,
    context::EnclaveContext,
    bridges::ocalls::save_to_host_memory,
    group_key::GroupKey,
    instructions::Instructions,
};

/// A trait for exporting transactions to out-enclave.
/// For calculated transaction in enclave which is ready to sending outside.
pub trait EnclaveTx: Sized {
    type R: RawEnclaveTx;

    fn into_raw(self) -> Result<Self::R>;
 }

/// A transaction components for JoinGroup operations.
#[derive(Debug, Clone)]
pub struct JoinGroupTx {
    report: AttestationReport,
    report_sig: ReportSig,
    handshake: HandshakeParams,
}

impl EnclaveTx for JoinGroupTx {
    type R = RawJoinGroupTx;

    fn into_raw(self) -> Result<Self::R> {
        let report = save_to_host_memory(&self.report.as_bytes())? as *const u8;
        let report_sig = save_to_host_memory(&self.report_sig.as_bytes())? as *const u8;
        let handshake = save_to_host_memory(&self.handshake.encode())? as *const u8;

        Ok(RawJoinGroupTx {
            report,
            report_sig,
            handshake,
        })
    }
}

impl JoinGroupTx {
    pub fn new(report: AttestationReport, report_sig: ReportSig, handshake: HandshakeParams) -> Self {
        JoinGroupTx {
            report,
            report_sig,
            handshake,
        }
    }

    pub fn construct<S: State>(
        ias_url: &str,
        ias_api_key: &str,
        ctx: &EnclaveContext<S>,
    ) -> Result<Self> {
        let quote = ctx.quote()?;
        let (report, report_sig) = RAService::remote_attestation(ias_url, ias_api_key, &quote)?;
        let group_key = ctx.group_key.read().unwrap();
        let handshake = group_key.create_handshake()?;

        Ok(JoinGroupTx {
            report,
            report_sig,
            handshake,
        })
    }
}

/// A transaction components for state transition operations.
#[derive(Debug, Clone)]
pub struct InstructionTx {
    state_id: u64,
    ciphertext: Ciphertext,
    enclave_sig: secp256k1::Signature,
    msg: Sha256,
}

impl EnclaveTx for InstructionTx {
    type R = RawInstructionTx;

    fn into_raw(self) -> Result<Self::R> {
        let ciphertext = save_to_host_memory(&self.ciphertext.into_vec())? as *const u8;
        let enclave_sig = save_to_host_memory(&self.enclave_sig.serialize())? as *const u8;
        let msg = save_to_host_memory(&self.msg.as_bytes())? as *const u8;

        Ok(RawInstructionTx {
            state_id: self.state_id,
            ciphertext,
            enclave_sig,
            msg,
        })
    }
}

impl InstructionTx {
    pub fn construct<R, G, S>(
        call_id: u32,
        params: &mut [u8],
        state_id: u64, // TODO: future works for separating smart contracts
        access_right: &AccessRight,
        enclave_ctx: &EnclaveContext<S>,
        max_mem_size: usize,
    ) -> Result<Self>
    where
        R: RuntimeExecutor<G, S>,
        G: StateGetter<S>,
        S: State,
    {
        let group_key = enclave_ctx.group_key.read().unwrap();
        let ciphertext = Instructions::<R, G, S>::new(call_id, params, &access_right)?
            .encrypt(&group_key, max_mem_size)?;
        let msg = Sha256::hash(&ciphertext.encode());
        let enclave_sig = enclave_ctx.sign(msg.as_bytes())?;

        Ok(InstructionTx {
            state_id,
            ciphertext,
            enclave_sig,
            msg,
        })
    }
}

/// A transaction components for handshake operations.
#[derive(Debug, Clone)]
pub struct HandshakeTx {
    handshake: HandshakeParams,
}

impl EnclaveTx for HandshakeTx {
    type R = RawHandshakeTx;

    fn into_raw(self) -> Result<Self::R> {
        let handshake = save_to_host_memory(&self.handshake.encode())? as *const u8;

        Ok(RawHandshakeTx { handshake })
    }
}

impl HandshakeTx {
    pub fn new(handshake: HandshakeParams) -> Self {
        HandshakeTx { handshake }
    }

    pub fn construct<S: State>(
        ctx: &EnclaveContext<S>,
    ) -> Result<Self> {
        let group_key = ctx.group_key.read().unwrap();
        let handshake = group_key.create_handshake()?;

        Ok(HandshakeTx { handshake })
    }
}
