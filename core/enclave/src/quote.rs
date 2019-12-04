use sgx_types::*;
use crate::error::{Result, EnclaveError};
use std::prelude::v1::*;
use sgx_tse::rsgx_create_report;
use crate::ocalls::{sgx_init_quote, get_quote};

/// spid: Service procider ID for the ISV.
#[derive(Clone)]
pub struct EnclaveContext {
    spid: sgx_spid_t,
}

// TODO: Consider SGX_ERROR_BUSY.
impl EnclaveContext {
    pub fn new(spid: &str) -> Result<Self> {
        let spid_vec = hex::decode(spid)?;
        let mut id = [0; 16];
        id.copy_from_slice(&spid_vec);
        let spid: sgx_spid_t = sgx_spid_t { id };

        Ok(EnclaveContext{ spid })
    }

    pub fn get_quote(&self) -> Result<String> {
        let target_info = self.init_quote()?;
        let report = self.get_report(&target_info)?;
        self.get_encoded_quote(report)
    }

    pub(crate) fn init_quote(&self) -> Result<sgx_target_info_t> {
        let target_info = sgx_init_quote()?;
        Ok(target_info)
    }

    fn get_report(&self, target_info: &sgx_target_info_t) -> Result<sgx_report_t> {
        let mut report = sgx_report_t::default();
        let report_data = sgx_report_data_t::default();

        if let Ok(r) = rsgx_create_report(&target_info, &report_data) {
            report = r;
        }

        Ok(report)
    }

    fn get_encoded_quote(&self, report: sgx_report_t) -> Result<String> {
        let quote = get_quote(report, &self.spid)?;

        // Use base64-encoded QUOTE structure to communicate via defined API.
        Ok(base64::encode(&quote))
    }
}
