#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[macro_use]
extern crate sgx_tstd as std;

use libsgx_test_utils::*;
use std::prelude::v1::*;

#[no_mangle]
pub fn ecall_run_tests() {
    
}
