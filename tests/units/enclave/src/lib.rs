#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

use lazy_static::lazy_static;
use std::backtrace;
use std::prelude::v1::*;
use test_utils::{runner::*, check_all_passed, run_tests};

lazy_static! {
    static ref ENABLE_BACKTRACE: () = {
        backtrace::enable_backtrace(
            &*frame_config::ENCLAVE_SIGNED_SO,
            backtrace::PrintFormat::Short,
        )
        .unwrap();
    };
}

#[no_mangle]
pub fn ecall_run_tests() {
    *ENABLE_BACKTRACE;

    let ret = check_all_passed!(
        frame_treekem::tests::run_tests(),
        anonify_enclave::tests::run_tests(),
        frame_mra_tls::tests::run_tests(),
    );

    assert!(ret);
}
