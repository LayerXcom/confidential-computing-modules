use std::vec::Vec;
use anonify_types::{RawRegisterTx, RawStateTransTx, RawHandshakeTx, traits::RawEnclaveTx};
use anonify_common::{UserAddress, LockParam, AccessRight, IntoVec};
use anonify_app_preluder::{Ciphertext, CallKind};
use anonify_runtime::{StateType, State, MemId};
use anonify_treekem::handshake::HandshakeParams;
use codec::Encode;
use remote_attestation::{RAService, AttestationReport, ReportSig};
use crate::{
    error::Result,
    context::EnclaveContext,
    bridges::ocalls::save_to_host_memory,
    state::{UserState, StateTransService},
    group_key::GroupKey,
};

/// A trait for exporting transactions to out-enclave.
/// For calculated transaction in enclave which is ready to sending outside.
pub trait EnclaveTx: Sized {
    type R: RawEnclaveTx;

    fn into_raw(self) -> Result<Self::R>;
 }

/// A transaction components for register operations.
#[derive(Debug, Clone)]
pub struct RegisterTx {
    report: AttestationReport,
    report_sig: ReportSig,
    handshake: HandshakeParams,
}

impl EnclaveTx for RegisterTx {
    type R = RawRegisterTx;

    fn into_raw(self) -> Result<Self::R> {
        let report = save_to_host_memory(&self.report.as_bytes())? as *const u8;
        let report_sig = save_to_host_memory(&self.report_sig.as_bytes())? as *const u8;
        let handshake = save_to_host_memory(&self.handshake.encode())? as *const u8;

        Ok(RawRegisterTx {
            report,
            report_sig,
            handshake,
        })
    }
}

impl RegisterTx {
    pub fn new(report: AttestationReport, report_sig: ReportSig, handshake: HandshakeParams) -> Self {
        RegisterTx {
            report,
            report_sig,
            handshake,
        }
    }

    pub fn construct(
        ias_url: &str,
        ias_api_key: &str,
        ctx: &EnclaveContext<StateType>,
    ) -> Result<Self> {
        let quote = ctx.quote()?;
        let (report, report_sig) = RAService::remote_attestation(ias_url, ias_api_key, &quote)?;
        let group_key = ctx.group_key.read().unwrap();
        let handshake = group_key.create_handshake()?;

        Ok(RegisterTx {
            report,
            report_sig,
            handshake,
        })
    }
}

/// A transaction components for state transition operations.
#[derive(Debug, Clone)]
pub struct StateTransTx {
    state_id: u64,
    ciphertexts: Vec<Ciphertext>,
    lock_params: Vec<LockParam>,
    enclave_sig: secp256k1::Signature,
//     blc_num: u64,
//     state_hash: Vec<u8>,
}

impl EnclaveTx for StateTransTx {
    type R = RawStateTransTx;

    fn into_raw(self) -> Result<Self::R> {
        let ciphertext = save_to_host_memory(&self.ciphertexts.into_vec())? as *const u8;
        let lock_param = save_to_host_memory(&self.lock_params.into_vec())? as *const u8;
        let enclave_sig = save_to_host_memory(&self.enclave_sig.serialize())? as *const u8;

        Ok(RawStateTransTx {
            state_id: self.state_id,
            ciphertext,
            lock_param,
            enclave_sig,
        })
    }
}

impl StateTransTx {
    pub fn construct(
        kind: CallKind,
        state_id: u64, // TODO: future works for separating smart contracts
        access_right: &AccessRight,
        enclave_ctx: &EnclaveContext<StateType>,
    ) -> Result<Self>
    {
        let mut service = StateTransService::<StateType>::from_access_right(access_right, enclave_ctx)?;
        service.apply(kind)?;

        let lock_params = service.create_lock_params();
        let group_key = enclave_ctx.group_key.read().unwrap();
        let ciphertexts = service.create_ciphertexts(&group_key)?;
        let enclave_sig = enclave_ctx.sign(&lock_params[0])?;

        Ok(StateTransTx {
            state_id,
            ciphertexts,
            lock_params,
            enclave_sig,
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
        ctx: &EnclaveContext<StateType>,
    ) -> Result<Self> {
        let group_key = ctx.group_key.read().unwrap();
        let handshake = group_key.create_handshake()?;

        Ok(HandshakeTx { handshake })
    }
}
