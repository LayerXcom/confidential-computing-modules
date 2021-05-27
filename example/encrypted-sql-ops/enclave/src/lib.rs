//! ecall_register!

#![deny(missing_debug_implementations, missing_docs)]
#![crate_name = "encrypted_sql_ops"]
#![crate_type = "staticlib"]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[macro_use]
extern crate sgx_tstd as std;

mod ecalls;

use lazy_static::lazy_static;
use log::debug;
use module_encrypted_sql_ops_enclave::enclave_context::EncryptedSqlOpsEnclaveContext;
use std::backtrace;

const ENCRYPTED_SQL_OPS_MRENCLAVE_VERSION: usize = 0;

lazy_static! {
    /// FIXME: I can't get what is this ... :sob:
    pub static ref ENCLAVE_CONTEXT: EncryptedSqlOpsEnclaveContext = {
        env_logger::init();
        debug!("encrypted-sql-ops enclave initializing");

        backtrace::enable_backtrace(
            &*frame_config::ENCLAVE_SIGNED_SO,
            backtrace::PrintFormat::Short,
        )
        .unwrap();
        EncryptedSqlOpsEnclaveContext::new(ENCRYPTED_SQL_OPS_MRENCLAVE_VERSION)
    };
}
