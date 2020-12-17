use crate::client::RAService;
use crate::error::{FrameRAError, Result};
use frame_types::UntrustedStatus;
use sgx_types::*;

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
    /// sgx_qe_report_info_t: Data structure that contains the information from app enclave and report gen- erated by Quoting Enclave.
    fn ocall_sgx_get_quote(
        p_retval: *mut UntrustedStatus,
        p_report: *const sgx_report_t,
        p_sgx_att_key_id: *const sgx_att_key_id_t,
        p_qe_report_info: *mut sgx_qe_report_info_t,
        p_quote: *mut u8,
        quote_size: u32,
    ) -> sgx_status_t;

    /// OCall to get target information of myself.
    /// Generates self target info from the self cryptographic report of an enclave
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
            return Err(FrameRAError::OcallError {
                status,
                function: "ocall_sgx_init_quote",
            });
        }
        if rt.is_err() {
            return Err(FrameRAError::UntrustedError {
                status: rt,
                function: "ocall_sgx_init_quote",
            });
        }

        Ok(Self {
            att_key_id,
            target_info,
            enclave_report: None,
        })
    }

    pub fn set_enclave_report(mut self, report_data: &sgx_report_data_t) -> Result<Self> {
        let enclave_report =
            sgx_tse::rsgx_create_report(&self.target_info, &report_data).map_err(|err| {
                FrameRAError::OcallError {
                    status: err,
                    function: "sgx_tse::rsgx_create_report",
                }
            })?;
        self.enclave_report = Some(enclave_report);
        Ok(self)
    }

    /// Create quote with attestation key ID and enclave's local report.
    pub fn create_quote(self) -> Result<RAService> {
        let mut rt = UntrustedStatus::default();
        let mut quote_len: u32 = 0;
        let status = unsafe {
            ocall_sgx_get_quote_size(&mut rt as _, &self.att_key_id as _, &mut quote_len as _)
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameRAError::OcallError {
                status,
                function: "ocall_sgx_get_quote_size",
            });
        }
        if rt.is_err() {
            return Err(FrameRAError::UntrustedError {
                status: rt,
                function: "ocall_sgx_get_quote_size",
            });
        }

        let mut qe_report_info = sgx_qe_report_info_t::default();
        let mut quote_nonce = sgx_quote_nonce_t::default();
        sgx_trts::trts::rsgx_read_rand(&mut quote_nonce.rand).map_err(FrameRAError::Others)?;
        qe_report_info.nonce = quote_nonce;

        let status = unsafe { sgx_self_target(&mut qe_report_info.app_enclave_target_info as _) };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameRAError::OcallError {
                status,
                function: "sgx_self_target",
            });
        }

        let mut quote = vec![0; quote_len as usize];
        let status = unsafe {
            ocall_sgx_get_quote(
                &mut rt as _,
                &self.enclave_report.unwrap() as _, // enclave_report must be set
                &self.att_key_id as _,
                &mut qe_report_info as _,
                quote.as_mut_ptr(),
                quote_len,
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameRAError::OcallError {
                status,
                function: "ocall_sgx_get_quote",
            });
        }
        if rt.is_err() {
            return Err(FrameRAError::UntrustedError {
                status: rt,
                function: "ocall_sgx_get_quote",
            });
        }

        // compares the input report MAC value with the calculated MAC value to determine whether the report is valid or not.
        let qe_report = qe_report_info.qe_report;
        sgx_tse::rsgx_verify_report(&qe_report)
            .map_err(FrameRAError::VerifyReportError)?;
        Self::verify_quote(qe_report.body.report_data, quote_nonce, &quote)?;

        Ok(RAService::new(base64::encode(&quote)))
    }

    /// verify the QUOTE it received is not modified by the untrusted SW stack, and not a replay.
    /// report.data[..32] = SHA256(p_nonce||p_quote)
    fn verify_quote(
        report_data: sgx_report_data_t,
        quote_nonce: sgx_quote_nonce_t,
        quote: &[u8],
    ) -> Result<()> {
        let mut rhs_vec = quote_nonce.rand.to_vec();
        rhs_vec.extend(quote);
        let rhs = sgx_tcrypto::rsgx_sha256_slice(&rhs_vec).map_err(FrameRAError::Others)?;
        let lhs = &report_data.d[..32];
        if rhs != lhs {
            return Err(FrameRAError::VerifyQuoteError {
                rhs: rhs.to_vec(),
                lhs: lhs.to_vec(),
            });
        }

        Ok(())
    }
}
