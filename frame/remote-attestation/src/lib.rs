#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

mod client;

pub use crate::client::{AttestationReport, RAService, ReportSig};
