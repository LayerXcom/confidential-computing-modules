use crate::ENCLAVE_CONTEXT;
use anonify_config::constants::*;
use anyhow::anyhow;
use codec::{Decode, Encode};
use frame_common::traits::{EcallInput, EcallOutput};
use frame_enclave::{register_ecall, EnclaveEngine};
use key_vault_enclave::workflow::*;
use secret_backup_state_transition::{Runtime, MAX_MEM_SIZE};
use std::{ptr, vec::Vec};

register_ecall!(
    enable_runtime = false,
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<KeyVaultEnclaveContext>, // TODO
    KeyVaultEnclaveContext,
    (START_SERVER_CMD, ServerStarter),
    (STOP_SERVER_CMD, ServerStopper),
);
