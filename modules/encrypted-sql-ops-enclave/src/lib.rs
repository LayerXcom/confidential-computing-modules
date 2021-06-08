//! Value Objects and domain services to execute SQL operations / encryption.
//!
//! All of them are designed to be only visible in enclave.
//!
//! Ideally, everything in this crate serves for any RDBMS's extension development.

#![deny(missing_debug_implementations, missing_docs)]
#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

pub mod aggregate_calc;
pub mod ecall_cmd_handler;
pub mod enclave_context;
pub mod error;
pub mod plain_types;
pub mod type_crypt;

///
#[cfg(debug_assertions)]
pub mod tests {
    use std::prelude::v1::*;
    use test_utils::check_all_passed;

    /// called from test-utils crate
    pub fn run_tests() -> bool {
        check_all_passed!(crate::plain_types::plain_avg_state::tests::run_tests(),)
    }
}
