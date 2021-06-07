use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_enclave_use_case, BasicEnclaveUseCase};
use key_vault_ecall_types::cmd::*;
use key_vault_enclave::{context::KeyVaultEnclaveContext, workflow::*};

#[allow(dead_code)]
struct DummyType;

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    0,
    DummyType,
    KeyVaultEnclaveContext,
    (START_SERVER_CMD, ServerStarter),
    (STOP_SERVER_CMD, ServerStopper),
);
