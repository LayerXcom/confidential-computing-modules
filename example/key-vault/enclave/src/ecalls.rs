use crate::ENCLAVE_CONTEXT;
use anyhow::anyhow;
use frame_enclave::{register_ecall, BasicEnclaveEngine};
use key_vault_ecall_types::cmd::*;
use key_vault_enclave::{context::KeyVaultEnclaveContext, workflow::*};
use std::{ptr, vec::Vec};

#[allow(dead_code)]
struct DummyType;

register_ecall!(
    &*ENCLAVE_CONTEXT,
    0,
    DummyType,
    KeyVaultEnclaveContext,
    (START_SERVER_CMD, ServerStarter),
    (STOP_SERVER_CMD, ServerStopper),
);
