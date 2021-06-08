use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_enclave_use_case, BasicEnclaveUseCase};
use module_encrypted_sql_ops_enclave::{
    enclave_context::EncryptedSqlOpsEnclaveContext,
    enclave_use_cases::{
        EncIntegerAvgFinalFuncUseCase, EncIntegerAvgStateFuncUseCase, EncIntegerFromUseCase,
    },
};

#[allow(dead_code)]
struct DummyType;

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    EncIntegerFromUseCase<EncryptedSqlOpsEnclaveContext>,
    EncIntegerAvgStateFuncUseCase<EncryptedSqlOpsEnclaveContext>,
    EncIntegerAvgFinalFuncUseCase<EncryptedSqlOpsEnclaveContext>,
);
