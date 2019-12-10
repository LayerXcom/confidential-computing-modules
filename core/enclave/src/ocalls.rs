use sgx_types::*;
use anonify_types::traits::SliceCPtr;
use std::vec::Vec;
use crate::auto_ffi::*;
use crate::error::*;

pub fn get_ias_socket() -> Result<i32> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut ias_sock : i32 = 0;

    let status = unsafe {
		ocall_get_ias_socket(
            &mut rt as *mut sgx_status_t,
            &mut ias_sock as *mut i32
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: status });
	}
	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: rt });
    }

    Ok(ias_sock)
}

pub fn sgx_init_quote() -> Result<sgx_target_info_t> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut target_info = sgx_target_info_t::default();
    let mut gid = sgx_epid_group_id_t::default();

    let status = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut target_info as *mut sgx_target_info_t,
            &mut gid as *mut sgx_epid_group_id_t,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: status });
	}
	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: rt });
    }

    Ok(target_info)
}

pub fn get_quote(report: sgx_report_t, spid: &sgx_spid_t) -> Result<Vec<u8>> {
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut quote_len: u32 = 0;
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut quote = vec![0u8; RET_QUOTE_BUF_LEN as usize];

    let status = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            std::ptr::null(), // p_sigrl
            0,                // sigrl_len
            &report as *const sgx_report_t,
            sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE, // quote_type
            spid as *const sgx_spid_t, // p_spid
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
	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: rt });
    }

    let _ = quote.split_off(quote_len as usize);
    Ok(quote)
}

// TODO: Replace u64 with *const u8, and pass it via the ocall using *const *const u8
pub fn save_to_host_memory(data: &[u8]) -> Result<u64> {
    let mut ptr = 0u64;
    match unsafe { ocall_save_to_memory(&mut ptr as *mut u64, data.as_c_ptr(), data.len()) } {
        sgx_status_t::SGX_SUCCESS => Ok(ptr),
        e => Err(e.into()),
    }
}
