//! ecall_register!

#![deny(missing_debug_implementations, missing_docs)]
#![crate_name = "encrypted_sql_ops_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[macro_use]
extern crate sgx_tstd as std;
