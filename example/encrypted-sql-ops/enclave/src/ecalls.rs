use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_ecall, EnclaveEngine};
use module_encrypted_sql_ops_enclave::context::EncryptedSqlOpsEnclaveContext;
use std::{ptr, vec::Vec};

#[allow(dead_code)]
struct DummyType;

register_ecall!(
    &*ENCLAVE_CONTEXT,
    0,
    DummyType,
    EncryptedSqlOpsEnclaveContext,
);
