use anonify_types::{RawJoinGroupTx, RawHandshakeTx, traits::RawEnclaveTx};
use anonify_common::{
    crypto::{Sha256, AccessRight, Ciphertext},
    traits::*,
    state_types::StateType,
    plugin_types::*,
};
use anonify_treekem::handshake::HandshakeParams;
use anonify_runtime::traits::*;
use codec::Encode;
use remote_attestation::{RAService, AttestationReport, ReportSig};
use crate::{
    error::Result,
    context::EnclaveContext,
    bridges::ocalls::save_to_host_memory,
    instructions::Instructions,
};

pub fn construct_instruction<R, C>(
    call_id: u32,
    params: &mut [u8],
    access_right: &AccessRight,
    enclave_ctx: &C,
    max_mem_size: usize,
) -> Result<output::Instruction>
where
    R: RuntimeExecutor<C, S=StateType>,
    C: ContextOps,
{
    let group_key = &*enclave_ctx.get_group_key();
    let ciphertext = Instructions::<R, C>::new(call_id, params, &access_right)?
        .encrypt(group_key, max_mem_size)?;
    let msg = Sha256::hash(&ciphertext.encode());
    let enclave_sig = enclave_ctx.sign(msg.as_bytes())?;

    Ok(output::Instruction::new(
        ciphertext,
        enclave_sig,
        msg,
    ))
}

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

    pub fn construct(
        ias_url: &str,
        ias_api_key: &str,
        ctx: &EnclaveContext,
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

    pub fn construct(
        ctx: &EnclaveContext,
    ) -> Result<Self> {
        let group_key = ctx.group_key.read().unwrap();
        let handshake = group_key.create_handshake()?;

        Ok(HandshakeTx { handshake })
    }
}
