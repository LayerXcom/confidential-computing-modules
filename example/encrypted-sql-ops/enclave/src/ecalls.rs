use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_enclave_use_case, BasicEnclaveUseCase};
use module_encrypted_sql_ops_enclave::enclave_use_cases::{
    EncIntegerAvgFinalFuncUseCase, EncIntegerAvgStateFuncUseCase, EncIntegerFromUseCase,
};
register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    EncIntegerFromUseCase,
    EncIntegerAvgStateFuncUseCase,
    EncIntegerAvgFinalFuncUseCase,
);
