use crate::StorePathSecrets;
use anyhow::Result;
use codec::Encode;
use frame_types::UntrustedStatus;
use log::debug;
use sgx_types::*;
use std::{
    net::{SocketAddr, TcpStream},
    os::unix::io::IntoRawFd,
    ptr, slice,
};

const DEV_HOSTNAME: &str = "api.trustedservices.intel.com";
const HTTPS_PORT: u16 = 443;

#[no_mangle]
pub extern "C" fn ocall_import_path_secret(
    path_secret: *mut u8,
    ps_len: usize,
    id: *const u8,
    id_len: usize,
) -> UntrustedStatus {
    let id = unsafe { slice::from_raw_parts(id, id_len) };

    match StorePathSecrets::new().load_from_local_filesystem(&id) {
        Ok(eps) => unsafe {
            ptr::copy_nonoverlapping(eps.encode().as_ptr(), path_secret, ps_len);
        },
        Err(e) => {
            println!("Failed to load path secret from local filesystem {:?}", e);
            return UntrustedStatus::error();
        }
    }

    UntrustedStatus::success()
}

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t,
) -> UntrustedStatus {
    let ret = unsafe { sgx_init_quote(ret_ti, ret_gid) };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_init_quote returned {}", ret);
        return UntrustedStatus::error();
    }

    UntrustedStatus::success()
}

#[no_mangle]
pub extern "C" fn ocall_get_quote(
    p_sigrl: *const u8,
    sigrl_len: u32,
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_spid: *const sgx_spid_t,
    p_nonce: *const sgx_quote_nonce_t,
    p_qe_report: *mut sgx_report_t,
    p_quote: *mut u8,
    _maxlen: u32,
    p_quote_len: *mut u32,
) -> UntrustedStatus {
    let mut real_quote_len: u32 = 0;

    let ret = unsafe { sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32) };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return UntrustedStatus::error();
    }

    println!("quote size = {}", real_quote_len);
    unsafe {
        *p_quote_len = real_quote_len;
    }

    let ret = unsafe {
        sgx_get_quote(
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_sigrl,
            sigrl_len,
            p_qe_report,
            p_quote as *mut sgx_quote_t,
            real_quote_len,
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return UntrustedStatus::error();
    }

    UntrustedStatus::success()
}

#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> UntrustedStatus {
    let addr = match lookup_ipv4(DEV_HOSTNAME, HTTPS_PORT) {
        Ok(addr) => addr,
        Err(_) => {
            debug!("Failed to lookup ipv4 address.");
            return UntrustedStatus::error();
        }
    };
    let sock = match TcpStream::connect(&addr) {
        Ok(sock) => sock,
        Err(_) => {
            debug!("[-] Connect tls server failed!");
            return UntrustedStatus::error();
        }
    };

    unsafe {
        *ret_fd = sock.into_raw_fd();
    }

    UntrustedStatus::success()
}

fn lookup_ipv4(host: &str, port: u16) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs()?;
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return Ok(addr);
        }
    }

    unreachable!("Cannot lookup address");
}

#[no_mangle]
pub extern "C" fn ocall_get_update_info(
    platform_blob: *const sgx_platform_info_t,
    enclave_trusted: i32,
    update_info: *mut sgx_update_info_bit_t,
) -> UntrustedStatus {
    let ret = unsafe { sgx_report_attestation_status(platform_blob, enclave_trusted, update_info) };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_report_attestation_status returned {}", ret);
        return UntrustedStatus::error();
    }

    UntrustedStatus::success()
}
