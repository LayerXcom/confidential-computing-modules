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
