use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_enclave_use_case, BasicEnclaveUseCase};
use key_vault_enclave::{context::KeyVaultEnclaveContext, use_case::*};

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    ServerStarter<KeyVaultEnclaveContext>,
    ServerStopper<KeyVaultEnclaveContext>,
);
