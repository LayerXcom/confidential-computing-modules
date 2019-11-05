use sgx_types::*;
use failure::Error;
use std::time;
use crate::error::SgxError;

// Referring to Intel SDK Developer Reference.
// https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf.
extern "C" {
    pub fn sgx_init_quote(
        p_target_info: *mut sgx_target_info_t,
        p_gid: *mut sgx_epid_group_id_t
    ) -> sgx_status_t;

    pub fn ecall_get_registration_quote(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        target_info: *const sgx_target_info_t,
        report: *mut sgx_report_t
    ) -> sgx_status_t;

    pub fn sgx_calc_quote_size(
        p_sig_rl: *const uint8_t,
        sig_rl_size: uint32_t,
        p_quote_size: *mut uint32_t
    ) -> sgx_status_t;

    pub fn sgx_get_quote(
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_sig_rl: *const uint8_t,
        sig_rl_size: uint32_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut sgx_quote_t,
        quote_size: uint32_t
    ) -> sgx_status_t;
}

/// eid: Enclave ID to identify the enclave that owns an evicted age.
/// spid: Service procider ID for the ISV.
#[derive(Clone)]
pub struct EnclaveContext {
    eid: sgx_enclave_id_t,
    spid: sgx_spid_t,
}

// TODO: Consider SGX_ERROR_BUSY.
impl EnclaveContext {
    pub fn new(eid: sgx_enclave_id_t, spid: sgx_spid_t) -> Self {
        EnclaveContext {
            eid,
            spid,
        }
    }

    fn init_quote(&self) -> Result<sgx_target_info_t, Error> {
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();
        let status = unsafe {
            // Defined in P.97 SDK developer reference.
            sgx_init_quote(&mut target_info, &mut gid)
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(SgxError {
                status,
                function: "sgx_init_quote",
            }.into());
        }

        Ok(target_info)
    }

    fn get_report(&self, target_info: &sgx_target_info_t) -> Result<sgx_report_t, Error> {
        let mut report = sgx_report_t::default();
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let status = unsafe {
            ecall_get_registration_quote(
                self.eid,
                &mut retval,
                target_info,
                &mut report
            )
        };

        if status != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
            return Err(SgxError {
                status,
                function: "ecall_get_registration_quote",
            }.into());
        }

        Ok(report)
    }

    fn calc_quote_size() -> Result<u32, Error> {
        let mut quote_size: u32 = 0;
        let status = unsafe {
            // Defined in P.157 SDK developer reference.
            sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size)
        };

        if status != sgx_status_t::SGX_SUCCESS || quote_size == 0 {
            return Err(SgxError {
                status,
                function: "sgx_calc_quote_size",
            }.into());
        }

        Ok(quote_size)
    }

    fn get_quote(&self, quote_size: u32, report: sgx_report_t) -> Result<Vec<u8>, Error> {
        let mut quote = vec![0u8; quote_size as usize];
        let status = unsafe {
            // Defined in P.100
            sgx_get_quote(
                &report,
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                &self.spid,
                std::ptr::null(), // nonce
                std::ptr::null(), // sig_rl
                0,                // sig_rl size
                std::ptr::null_mut(),
                quote.as_mut_ptr() as *mut sgx_quote_t,
                quote_size,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(SgxError {
                status,
                function: "sgx_get_quote"
            }.into());
        }

        Ok(quote)
    }
}
