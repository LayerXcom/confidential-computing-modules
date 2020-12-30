#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "backup-enable")]
use anonify_enclave_backup_enabled as anonify_enclave;
#[cfg(feature = "backup-disable")]
use anonify_enclave_backup_disabled as anonify_enclave;

use std::prelude::v1::*;
use test_utils::*;

#[no_mangle]
pub fn ecall_run_tests() {
    let ret = check_all_passed!(
        frame_treekem::tests::run_tests(),
        anonify_enclave::tests::run_tests(),
        frame_mra_tls::tests::run_tests(),
    );

    assert!(ret);
}
