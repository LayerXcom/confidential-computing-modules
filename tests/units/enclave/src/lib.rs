#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

use libsgx_test_utils::*;
use std::prelude::v1::*;

#[no_mangle]
pub fn ecall_run_tests() {
    let ret = check_all_passed!(
        frame_treekem::tests::run_tests(),
    );

    assert!(ret);
}
