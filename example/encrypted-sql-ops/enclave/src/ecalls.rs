use crate::ENCLAVE_CONTEXT;
use anyhow::anyhow;
use bincode::Options;
use frame_enclave::{register_ecall, BasicEnclaveEngine};
use log::error;
use module_encrypted_sql_ops_ecall_types::ecall_cmd::*;
use module_encrypted_sql_ops_enclave::{
    ecall_cmd_handler::{
        EncIntegerAvgFinalFuncCmdHandler, EncIntegerAvgStateFuncCmdHandler,
        EncIntegerFromCmdHandler,
    },
    enclave_context::EncryptedSqlOpsEnclaveContext,
};
use std::{ptr, vec::Vec};

#[allow(dead_code)]
struct DummyType;

register_ecall!(
    &*ENCLAVE_CONTEXT,
    0,
    DummyType,
    EncryptedSqlOpsEnclaveContext,
    (ENCINTEGER_FROM, EncIntegerFromCmdHandler),
    (ENCINTEGER_AVG_STATE_FUNC, EncIntegerAvgStateFuncCmdHandler),
    (ENCINTEGER_AVG_FINAL_FUNC, EncIntegerAvgFinalFuncCmdHandler),
);
