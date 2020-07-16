use std::{
    vec::Vec,
    ptr,
};
use anonify_types::*;
use anonify_common::{
    plugin_types::*,
    commands::*,
};
use anonify_enclave::context::EnclaveContext;
use invoice_state_transition::{MAX_MEM_SIZE, Runtime};
use crate::ENCLAVE_CONTEXT;
use anonify_enclave::bridges::ecall_handler::*;
use anonify_ecalls::register_ecall;
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
    (JOIN_GROUP_CMD, input::CallJoinGroup, output::ReturnJoinGroup),
    (HANDSHAKE_CMD, input::CallHandshake, output::ReturnHandshake),
);

#[no_mangle]
pub unsafe extern "C" fn ecall_register_notification(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_register_notification(
        sig,
        pubkey,
        challenge,
        &*ENCLAVE_CONTEXT,
    ) {
        println!("Error (ecall_register_notification): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}
