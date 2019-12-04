use sgx_types::*;
use crate::auto_ffi::*;
use crate::error::*;

pub fn get_ias_socket() -> Result<i32> {
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut ias_sock : i32 = 0;

    let res = unsafe {
		ocall_get_ias_socket(
            &mut rt as *mut sgx_status_t,
            &mut ias_sock as *mut i32
        )
    };

    if res != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: res });
	}

	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(EnclaveError::SgxError{ err: rt });
    }

    Ok(ias_sock)
}
