use crate::error::{FrameEnclaveError, Result};
use anyhow::anyhow;
use codec::Decode;
use frame_common::crypto::{ExportPathSecret, EXPORT_ID_SIZE, EXPORT_PATH_SECRET_SIZE};
use frame_types::UntrustedStatus;
use sgx_types::*;
use std::vec::Vec;

extern "C" {
    pub fn ocall_import_path_secret(
        retval: *mut UntrustedStatus,
        path_secret: *mut u8,
        ps_len: usize,
        id: *const u8,
        id_len: usize,
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
            buf.as_mut_ptr(),
            EXPORT_PATH_SECRET_SIZE,
            id.as_ptr(),
            EXPORT_ID_SIZE,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(FrameEnclaveError::SgxError { err: status });
    }
    if rt.is_err() {
        return Err(FrameEnclaveError::UntrustedError {
            status: rt,
            function: "ocall_import_path_secret",
        });
    }

    let exported_path_secret =
        ExportPathSecret::decode(&mut &buf[..]).map_err(FrameEnclaveError::CodecError)?;
    if id != exported_path_secret.id() {
        return Err(anyhow!("Invalid path_secret's id").into());
    }

    Ok(exported_path_secret)
}
