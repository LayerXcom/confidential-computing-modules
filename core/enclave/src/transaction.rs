use anonify_types::{RawRegisterTx, traits::RawEnclaveTx};
use crate::{
    attestation::{Report, ReportSig},
    error::Result,
};

pub trait EnclaveTx: Sized {
    type R: RawEnclaveTx;

    fn construct() -> Result<Self>;

    fn into_raw() -> Self::R;
 }

// impl<U, T> From<U> for T
// where
//     U: EnclaveTx,
//     T: RawEnclaveTx,
// {
//     fn from(e: U) -> Self {
//         e.into_raw()
//     }
// }

#[derive(Debug, Clone)]
pub struct RegisterTx {
    report: Report,
    report_sig: ReportSig,
    // AddHandShake
}

impl EnclaveTx for RegisterTx {
    type R = RawRegisterTx;

    fn construct() -> Result<Self> {
        unimplemented!();
    }

    fn into_raw() -> Self::R {
        unimplemented!();
    }
}

impl RegisterTx {
    pub fn new(report: Report, report_sig: ReportSig) -> Self {
        RegisterTx {
            report,
            report_sig,
        }
    }
}

// #[derive(Debug, Clone)]
// pub struct StateTransitionTx {
//     ciphertexts: Vec<Ciphertext>,
//     lock_param: Vec<u8>,
//     blc_num: u64,
//     state_hash: Vec<u8>,
//     enclave_sig: Vec<u8>,
// }

