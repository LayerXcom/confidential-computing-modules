use crate::ENCLAVE_CONTEXT;
use anonify_enclave::context::EnclaveContext;
use anyhow::anyhow;
use codec::{Decode, Encode};
use config::constants::*;
use frame_common::traits::{EcallInput, EcallOutput};
use frame_enclave::{register_ecall, EnclaveEngine};
use key_vault_enclave::workflow::*;
use key_vault_example_state_transition::{Runtime, MAX_MEM_SIZE};
use std::{ptr, vec::Vec};

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<EnclaveContext>,
    EnclaveContext,
    (START_SERVER_CMD, ServerStarter),
    (STOP_SERVER_CMD, ServerStopper),
);
