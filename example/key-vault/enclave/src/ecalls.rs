use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_enclave_use_case, BasicEnclaveUseCase};
use key_vault_ecall_types::cmd::*;
use key_vault_enclave::{context::KeyVaultEnclaveContext, workflow::*};

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    (START_SERVER_CMD, ServerStarter<KeyVaultEnclaveContext>),
    (STOP_SERVER_CMD, ServerStopper<KeyVaultEnclaveContext>),
);
