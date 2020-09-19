use frame_types::UntrustedStatus;
use frame_common::crypto::{ExportPathSecret, EXPORT_PATH_SECRET_SIZE, EXPORT_ID_SIZE};
use sgx_types::*;
use std::vec::Vec;
use anyhow::anyhow;
use codec::Decode;
use crate::error::{Result, FrameEnclaveError};

extern "C" {
    pub fn ocall_import_path_secret(
        retval: *mut UntrustedStatus,
        path_secret: *mut u8,
        ps_len: usize,
        id: *const u8,
        id_len: usize,
    ) -> sgx_status_t;
}
extern "C" {
    pub fn ocall_sgx_init_quote(
        retval: *mut UntrustedStatus,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
}
extern "C" {
    pub fn ocall_get_quote(
        retval: *mut UntrustedStatus,
        p_sigrl: *const u8,
        sigrl_len: u32,
        report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut sgx_quote_t,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}
extern "C" {
    pub fn ocall_get_ias_socket(
        retval: *mut UntrustedStatus,
        ret_fd: *mut ::std::os::raw::c_int,
    ) -> sgx_status_t;
}
extern "C" {
    pub fn ocall_get_update_info(
        retval: *mut UntrustedStatus,
        platformBlob: *mut sgx_platform_info_t,
        enclaveTrusted: i32,
        update_info: *mut sgx_update_info_bit_t,
    ) -> sgx_status_t;
}

pub fn import_path_secret(id: &[u8]) -> anyhow::Result<ExportPathSecret> {
    let mut id_arr = [0u8; EXPORT_ID_SIZE];
    id_arr.copy_from_slice(&id);
    inner_import_path_secret(id_arr).map_err(Into::into)
}

fn inner_import_path_secret(id: [u8; EXPORT_ID_SIZE]) -> Result<ExportPathSecret> {
    let mut rt = UntrustedStatus::default();
    let mut buf = [0u8; EXPORT_PATH_SECRET_SIZE];

    let status = unsafe {
        ocall_import_path_secret(
            &mut rt as *mut UntrustedStatus,
            buf.as_mut_ptr() as *mut u8,
            EXPORT_PATH_SECRET_SIZE,
            id.as_ptr() as *const u8,
            EXPORT_ID_SIZE
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(FrameEnclaveError::SgxError{ err: status });
	}
	if rt.is_err() {
		return Err(FrameEnclaveError::UntrustedError{ status: rt, function: "ocall_import_path_secret" });
    }

    let exported_path_secret = ExportPathSecret::decode(&mut &buf[..])
        .map_err(|e| FrameEnclaveError::CodecError(e))?;
    if id == exported_path_secret.id() {
        return Err(anyhow!("Invalid path_secret's id").into());
    }

    Ok(exported_path_secret)
}

pub fn get_ias_socket() -> Result<i32> {
    let mut rt = UntrustedStatus::default();
    let mut ias_sock : i32 = 0;

    let status = unsafe {
		ocall_get_ias_socket(
            &mut rt as *mut UntrustedStatus,
            &mut ias_sock as *mut i32
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(FrameEnclaveError::SgxError{ err: status });
	}
	if rt.is_err() {
		return Err(FrameEnclaveError::UntrustedError{ status: rt, function: "ocall_get_ias_socket" });
    }

    Ok(ias_sock)
}

pub fn sgx_init_quote() -> Result<sgx_target_info_t> {
    let mut rt = UntrustedStatus::default();
    let mut target_info = sgx_target_info_t::default();
    let mut gid = sgx_epid_group_id_t::default();

    let status = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut UntrustedStatus,
            &mut target_info as *mut sgx_target_info_t,
            &mut gid as *mut sgx_epid_group_id_t,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(FrameEnclaveError::SgxError{ err: status });
	}
	if rt.is_err() {
        return Err(FrameEnclaveError::UntrustedError{ status: rt, function: "ocall_sgx_init_quote" });
    }

    Ok(target_info)
}

pub fn get_quote(report: sgx_report_t, spid: &sgx_spid_t) -> Result<Vec<u8>> {
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut quote_len: u32 = 0;
    let mut rt = UntrustedStatus::default();
    let mut quote = vec![0u8; RET_QUOTE_BUF_LEN as usize];

    let status = unsafe {
        ocall_get_quote(
            &mut rt as *mut UntrustedStatus,
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
		return Err(FrameEnclaveError::SgxError{ err: status });
	}
	if rt.is_err() {
        return Err(FrameEnclaveError::UntrustedError{ status: rt, function: "ocall_get_quote" });
    }

    let _ = quote.split_off(quote_len as usize);
    Ok(quote)
}

pub fn get_update_info(buf: Vec<u8>) -> Result<()> {
    let mut update_info = sgx_update_info_bit_t::default();
    let mut rt = UntrustedStatus::default();

    let status = unsafe {
        ocall_get_update_info(
            &mut rt as *mut UntrustedStatus,
            buf.as_slice().as_ptr() as *mut sgx_platform_info_t,
            1,
            &mut update_info as *mut sgx_update_info_bit_t
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(FrameEnclaveError::SgxError{ err: status });
	}
	if rt.is_err() {
        return Err(FrameEnclaveError::UntrustedError{ status: rt, function: "ocall_get_update_info" });
    }

    Ok(())
}
