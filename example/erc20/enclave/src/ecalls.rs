use std::{
    vec::Vec,
    ptr,
};
use frame_types::*;
use anonify_common::{
    plugin_types::*,
    commands::*,
};
use frame_common::traits::{EcallInput, EcallOutput};
use anonify_enclave::context::EnclaveContext;
use erc20_state_transition::{MAX_MEM_SIZE, Runtime};
use crate::ENCLAVE_CONTEXT;
use anonify_enclave::bridges::ecall_handler::*;
use frame_enclave::{register_ecall, EcallHandler};
use anyhow::anyhow;
use codec::Encode;

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<EnclaveContext>,
    EnclaveContext,
    (ENCRYPT_INSTRUCTION_CMD, input::Instruction, output::Instruction),
    // Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (INSERT_CIPHERTEXT_CMD, input::InsertCiphertext, output::ReturnUpdatedState),
    // Insert handshake received from blockchain nodes into enclave.
    (INSERT_HANDSHAKE_CMD, input::InsertHandshake, output::Empty),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, input::GetState, output::ReturnState),
    (CALL_JOIN_GROUP_CMD, input::CallJoinGroup, output::ReturnJoinGroup),
    (CALL_HANDSHAKE_CMD, input::CallHandshake, output::ReturnHandshake),
    (REGISTER_NOTIFICATION_CMD, input::RegisterNotification, output::Empty),
);
