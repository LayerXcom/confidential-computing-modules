use anyhow::Result;
use frame_types::UntrustedStatus;
use std::sgx_types::*;
use crate::client::RAService;

extern "C" {
    /// Ocall to use sgx_init_quote_ex to init the quote and key_id.
    /// p_att_key_id: Selected attestation key ID returned by sgx_select_att_key_id.
    /// p_target_info: Allows an enclave for that the quote is being created to create the report that only QE can verify.
    pub fn ocall_sgx_init_quote(
        p_retval: *mut UntrustedStatus,
        p_sgx_att_key_id: *mut sgx_att_key_id_t,
        p_target_info: *mut sgx_target_info_t,
    ) -> sgx_status_t;

    /// Ocall to get the required buffer size for the quote.
    fn ocall_sgx_get_quote_size(
        p_retval: *mut UntrustedStatus,
        p_sgx_att_key_id: *const sgx_att_key_id_t,
        p_quote_size: *mut u32,
    ) -> sgx_status_t;

    /// Ocall to use sgx_get_quote_ex to generate a quote with enclave's report.
    fn ocall_sgx_get_quote(
        p_retval: *mut sgx_status_t,
        p_report: *const sgx_report_t,
        p_sgx_att_key_id: *const sgx_att_key_id_t,
        p_qe_report_info: *mut sgx_qe_report_info_t,
        p_quote: *mut u8,
        quote_size: u32,
    ) -> sgx_status_t;

    /// OCall to get target information of myself.
    fn sgx_self_target(p_target_info: *mut sgx_target_info_t) -> sgx_status_t;
}

#[derive(Clone, Copy, Default)]
pub struct Quote {
    att_key_id: sgx_att_key_id_t,
    target_info: sgx_target_info_t,
    enclave_report: Option<sgx_report_t>,
}

impl Quote {
    /// Returns information required by an Intel® SGX application to get a quote of one of its enclaves.
    pub fn new() -> Result<Self> {
        let mut rt = UntrustedStatus::default();
        let mut att_key_id = sgx_att_key_id_t::default();
        let mut target_info = sgx_target_info_t::default();

        let status = unsafe {
            ocall_sgx_init_quote(
                &mut rt as *mut UntrustedStatus,
                &mut att_key_id as _,
                &mut target_info as _,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameEnclaveError::SgxError { err: status });
        }
        if rt.is_err() {
            return Err(FrameEnclaveError::UntrustedError {
                status: rt,
                function: "ocall_sgx_init_quote",
            });
        }

        Ok(Self {
            att_key_id,
            target_info,
        })
    }

    pub fn create_enclave_report(mut self, report_data: &sgx_report_data_t) -> Result<Self> {
        let enclave_report =
            sgx_tse::rsgx_create_report(&self.target_info, &report_data).map_err(Into::into)?;
        self.enclave_report = Some(enclave_report);
        Ok(self)
    }

    /// Get quote with attestation key ID and enclave's local report.
    pub fn create_quote(self) -> Result<RAService> {
        unimplemented!();
    }
}

// pub fn get_quote(report: sgx_report_t, spid: &sgx_spid_t) -> Result<Vec<u8>> {
//     const RET_QUOTE_BUF_LEN: u32 = 2048;
//     let mut quote_len: u32 = 0;
//     let mut rt = UntrustedStatus::default();
//     let mut quote = vec![0u8; RET_QUOTE_BUF_LEN as usize];

//     let status = unsafe {
//         ocall_get_quote(
//             &mut rt as *mut UntrustedStatus,
//             std::ptr::null(), // p_sigrl
//             0,                // sigrl_len
//             &report as *const sgx_report_t,
//             sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE, // quote_type
//             spid as *const sgx_spid_t,                       // p_spid
//             std::ptr::null(),                                // p_nonce
//             std::ptr::null_mut(),                            // p_qe_report
//             quote.as_mut_ptr() as *mut sgx_quote_t,
//             RET_QUOTE_BUF_LEN, // maxlen
//             &mut quote_len as *mut u32,
//         )
//     };

//     if status != sgx_status_t::SGX_SUCCESS {
//         return Err(FrameEnclaveError::SgxError { err: status });
//     }
//     if rt.is_err() {
//         return Err(FrameEnclaveError::UntrustedError {
//             status: rt,
//             function: "ocall_get_quote",
//         });
//     }

//     let _ = quote.split_off(quote_len as usize);
//     Ok(quote)
// }
