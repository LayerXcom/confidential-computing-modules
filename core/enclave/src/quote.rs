use sgx_types::*;
use crate::error::{Result, EnclaveError};
use std::prelude::v1::*;
use sgx_tse::rsgx_create_report;
use crate::auto_ffi::*;

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
        self.inner_get_quote(report)
    }

    pub(crate) fn init_quote(&self) -> Result<sgx_target_info_t> {
        let mut status = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();

        let status = unsafe {
            ocall_sgx_init_quote(
                &mut status as *mut sgx_status_t,
                &mut target_info as *mut sgx_target_info_t,
                &mut gid as *mut sgx_epid_group_id_t,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(EnclaveError::SgxError{ err: status });
        }

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

    fn inner_get_quote(&self, report: sgx_report_t) -> Result<String> {
        const RET_QUOTE_BUF_LEN : u32 = 2048;
        let mut quote_len: u32 = 0;
        let mut status = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let mut quote = vec![0u8; RET_QUOTE_BUF_LEN as usize];

        let status = unsafe {
            ocall_get_quote(
                &mut status as *mut sgx_status_t,
                std::ptr::null(), // p_sigrl
                0,                // sigrl_len
                &report as *const sgx_report_t,
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE, // quote_type
                &self.spid as *const sgx_spid_t, // p_spid
                std::ptr::null(), // p_nonce
                std::ptr::null_mut(), // p_qe_report
                quote.as_mut_ptr() as *mut sgx_quote_t,
                RET_QUOTE_BUF_LEN, // maxlen
                &mut quote_len as *mut u32,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(EnclaveError::SgxError{ err: status });
        }

        // Use base64-encoded QUOTE structure to communicate via defined API.
        Ok(base64::encode(&quote[..]))
    }
}
