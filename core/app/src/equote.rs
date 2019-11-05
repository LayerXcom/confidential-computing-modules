use sgx_types::*;
use failure::Error;
use std::time;
use crate::error;

extern "C" {
    pub fn sgx_init_quote(
        p_target_info: *mut sgx_target_info_t,
        p_gid: *mut sgx_epid_group_id_t
    ) -> sgx_status_t;


}

/// eid: Enclave ID to identify the enclave that owns an evicted age.
/// spid: Service procider ID for the ISV.
#[derive(Clone)]
pub struct EnclaveContext {
    eid: sgx_enclave_id_t,
    spid: sgx_spid_t,
}

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
        let status = unsafe { sgx_init_quote(&mut target_info, &mut gid) };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(error::SgxError {
                status,
                function: "sgx_init_quote"
            }.into());
        }

        Ok(target_info)
    }
}

