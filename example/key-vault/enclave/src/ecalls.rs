use crate::ENCLAVE_CONTEXT;
use frame_enclave::{register_enclave_use_case, BasicEnclaveUseCase};
use key_vault_enclave::use_case::*;

register_enclave_use_case!(
    (ServerStarter, &*ENCLAVE_CONTEXT),
    (ServerStopper, &*ENCLAVE_CONTEXT),
);
