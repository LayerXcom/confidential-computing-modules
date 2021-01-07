use crate::ENCLAVE_CONTEXT;
use anonify_config::constants::*;
use anyhow::anyhow;
use codec::{Decode, Encode};
use frame_common::traits::{EcallInput, EcallOutput};
use frame_enclave::{register_ecall, EnclaveEngine};
use key_vault_enclave::{workflow::*, context::KeyVaultEnclaveContext};
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
