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

pub fn create_instruction_output<R, C>(
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
    let group_key = &*enclave_ctx.read_group_key();
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
