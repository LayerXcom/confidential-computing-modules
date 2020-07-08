use anonify_types::*;
use anonify_common::state_types::StateType;
use anonify_runtime::traits::*;
use anonify_enclave::{
    config::{IAS_URL, TEST_SUB_KEY},
    context::EnclaveContext,
};
use erc20_state_transition::{CIPHERTEXT_SIZE, MAX_MEM_SIZE, Runtime};
use crate::ENCLAVE_CONTEXT;
use anonify_enclave::bridges::inner_ecalls::*;

type Context = EnclaveContext;

/// Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_ciphertext(
    ciphertext: *mut u8,
    ciphertext_len: usize,
    raw_updated_state: &mut RawUpdatedState,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_insert_ciphertext::<Runtime<EnclaveContext>, EnclaveContext>(
        ciphertext,
        ciphertext_len,
        raw_updated_state,
        CIPHERTEXT_SIZE,
        &*ENCLAVE_CONTEXT,
    ) {
        println!("Error (ecall_insert_ciphertext): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

/// Insert handshake received from blockchain nodes into enclave.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_handshake(
    handshake: *mut u8,
    handshake_len: usize,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_insert_handshake(
        handshake,
        handshake_len,
        &*ENCLAVE_CONTEXT,
    ) {
        println!("Error (ecall_insert_handshake): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

/// Get current state of the user represented the given public key from enclave memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_get_state(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge, // 32 bytes randomness for avoiding replay attacks.
    mem_id: u32,
    state: &mut EnclaveState,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_get_state(
        sig,
        pubkey,
        challenge,
        mem_id,
        state,
        &*ENCLAVE_CONTEXT,
    ) {
        println!("Error (ecall_get_state): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_join_group(
    raw_join_group_tx: &mut RawJoinGroupTx,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_join_group(
        raw_join_group_tx,
        &*ENCLAVE_CONTEXT,
        IAS_URL,
        TEST_SUB_KEY,
    ) {
        println!("Error (ecall_join_group): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_instruction(
    raw_sig: &RawSig,
    raw_pubkey: &RawPubkey,
    raw_challenge: &RawChallenge,
    state: *mut u8,
    state_len: usize,
    state_id: u64,
    call_id: u32,
    raw_instruction_tx: &mut RawInstructionTx,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_instruction::<Runtime<EnclaveContext>, EnclaveContext>(
        raw_sig,
        raw_pubkey,
        raw_challenge,
        state,
        state_len,
        state_id,
        call_id,
        raw_instruction_tx,
        &*ENCLAVE_CONTEXT,
        MAX_MEM_SIZE,
    ) {
        println!("Error (ecall_instruction): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_handshake(
    raw_handshake_tx: &mut RawHandshakeTx,
) -> EnclaveStatus {
    if let Err(e) = inner_ecall_handshake(
        raw_handshake_tx,
        &*ENCLAVE_CONTEXT,
    ) {
        println!("Error (ecall_handshake): {}", e);
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

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
