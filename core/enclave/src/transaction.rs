use std::vec::Vec;
use anonify_types::{RawRegisterTx, RawStateTransTx, traits::RawEnclaveTx};
use anonify_common::{UserAddress, LockParam, AccessRight, IntoVec};
use anonify_app_preluder::{Ciphertext, CallKind};
use anonify_runtime::{StateType, State, MemId};
use crate::{
    attestation::{Report, ReportSig, AttestationService},
    error::Result,
    context::EnclaveContext,
    bridges::ocalls::save_to_host_memory,
    state::{UserState, StateService},
    crypto::SYMMETRIC_KEY,
};

/// A trait for exporting transacitons to out-enclave.
/// For calculated transaction in enclacve which is ready to sending outside.
pub trait EnclaveTx: Sized {
    type R: RawEnclaveTx;

    fn into_raw(self) -> Result<Self::R>;
 }

/// A transaction components for register operations.
#[derive(Debug, Clone)]
pub struct RegisterTx {
    report: Report,
    report_sig: ReportSig,
    // AddHandShake
}

impl EnclaveTx for RegisterTx {
    type R = RawRegisterTx;

    fn into_raw(self) -> Result<Self::R> {
        let report = save_to_host_memory(&self.report.as_bytes())? as *const u8;
        let report_sig = save_to_host_memory(&self.report_sig.as_bytes())? as *const u8;

        Ok(RawRegisterTx {
            report,
            report_sig,
        })
    }
}

impl RegisterTx {
    pub fn new(report: Report, report_sig: ReportSig) -> Self {
        RegisterTx {
            report,
            report_sig,
        }
    }

    pub fn construct(
        host: &str,
        path: &str,
        ias_api_key: &str,
        ctx: &EnclaveContext<StateType>,
    ) -> Result<Self> {
        let service = AttestationService::new(host, path);
        let quote = ctx.quote()?;
        let (report, report_sig) = service.report_and_sig_new(&quote, ias_api_key)?;

        Ok(RegisterTx {
            report,
            report_sig,
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
        state_id: u64,
        access_right: &AccessRight,
        enclave_ctx: &EnclaveContext<StateType>,
    ) -> Result<Self>
    {
        let mut service = StateService::<StateType>::from_access_right(access_right, enclave_ctx)?;
        service.apply(kind)?;

        let lock_params = service.reveal_lock_params();
        let ciphertexts = service.reveal_ciphertexts(&SYMMETRIC_KEY)?;
        let enclave_sig = enclave_ctx.sign(&lock_params[0])?;

        Ok(StateTransTx {
            state_id,
            ciphertexts,
            lock_params,
            enclave_sig,
        })
    }
}
