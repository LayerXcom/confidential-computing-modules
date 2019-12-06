use sgx_types::*;
use std::{
    net::{TcpStream, SocketAddr},
    os::unix::io::IntoRawFd,
    ptr,
    slice,
};
use crate::constants::{DEV_HOSTNAME, HTTPS_PORT};

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t
) -> sgx_status_t {
    unsafe { sgx_init_quote(ret_ti, ret_gid) }
}

#[no_mangle]
pub extern "C"
fn ocall_get_quote(
    p_sigrl: *const u8,
    sigrl_len: u32,
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_spid: *const sgx_spid_t,
    p_nonce: *const sgx_quote_nonce_t,
    p_qe_report: *mut sgx_report_t,
    p_quote: *mut u8,
    _maxlen: u32,
    p_quote_len: *mut u32) -> sgx_status_t {
    let mut real_quote_len : u32 = 0;

    let ret = unsafe {
        sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    println!("quote size = {}", real_quote_len);
    unsafe { *p_quote_len = real_quote_len; }

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
            real_quote_len
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    ret
}

#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd : *mut c_int) -> sgx_status_t {
    let addr = lookup_ipv4(DEV_HOSTNAME, HTTPS_PORT);
	let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

	unsafe { *ret_fd = sock.into_raw_fd(); }

	sgx_status_t::SGX_SUCCESS
}

fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
	use std::net::ToSocketAddrs;

	let addrs = (host, port).to_socket_addrs().unwrap();
	for addr in addrs {
		if let SocketAddr::V4(_) = addr {
			return addr;
		}
	}

	unreachable!("Cannot lookup address");
}

#[no_mangle]
pub unsafe extern "C" fn ocall_save_to_memory(data_ptr: *const u8, data_len: usize) -> u64 {
    let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
    let ptr = Box::into_raw(Box::new(data.into_boxed_slice())) as *const u8;
    ptr as u64
}
