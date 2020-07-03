use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{
    crypto::{UserAddress, AccessRight, Ciphertext},
    traits::*,
    state_types::MemId,
};
use anonify_runtime::traits::*;
use anonify_treekem::handshake::HandshakeParams;
use ed25519_dalek::{PublicKey, Signature};
use codec::Decode;
use log::debug;
use crate::{
    transaction::{JoinGroupTx, EnclaveTx, HandshakeTx, InstructionTx},
    instructions::Instructions,
    notify::updated_state_into_raw,
    bridges::ocalls::save_to_host_memory,
    context::EnclaveContext,
};

pub fn inner_ecall_insert_ciphertext<R, C, S>(
    ciphertext: *mut u8,
    ciphertext_len: usize,
    raw_updated_state: &mut RawUpdatedState,
    ciphertext_size: usize,
    enclave_context: C,
) -> EnclaveStatus
where
    R: RuntimeExecutor<C, S>,
    C: ContextOps<S> + Clone,
    S: State,
{
    let buf = unsafe{ slice::from_raw_parts_mut(ciphertext, ciphertext_len) };
    let ciphertext = Ciphertext::from_bytes(buf, ciphertext_size);
    let group_key = &mut *enclave_context.get_group_key();

    match Instructions::<R, C, S>::state_transition(enclave_context.clone(), &ciphertext, group_key) {
        Ok(iter_op) => {
            if let Some(updated_state_iter) = iter_op {
                if let Some(updated_state) = enclave_context.update_state(updated_state_iter) {
                    match updated_state_into_raw(updated_state) {
                        Ok(new) => *raw_updated_state = new,
                        Err(_) => {
                            debug!("Failed updated_state_into_raw(updated_state)");
                            return EnclaveStatus::error();
                        }
                    }
                }
            }
        },
        Err(_) => {
            debug!("Failed Instructions::state_transition");
            return EnclaveStatus::error();
        },
    }

    let roster_idx = ciphertext.roster_idx() as usize;
    // ratchet app keychain per a log.
    if group_key.ratchet(roster_idx).is_err() {
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

pub fn inner_ecall_insert_handshake<S: State>(
    handshake: *mut u8,
    handshake_len: usize,
    enclave_context: EnclaveContext<S>,
) -> EnclaveStatus {
    let handshake_bytes = unsafe{ slice::from_raw_parts_mut(handshake, handshake_len) };
    let handshake = match HandshakeParams::decode(&mut &handshake_bytes[..]) {
        Ok(handshake) => handshake,
        Err(_) => return EnclaveStatus::error(),
    };
    let group_key = &mut *match enclave_context.group_key.write() {
        Ok(group_key) => group_key,
        Err(_) => return EnclaveStatus::error(),
    };

    if group_key.process_handshake(&handshake).is_err() {
        return EnclaveStatus::error();
    }

    EnclaveStatus::success()
}

pub fn inner_ecall_get_state<S: State>(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge, // 32 bytes randomness for avoiding replay attacks.
    mem_id: u32,
    state: &mut EnclaveState,
    enclave_context: EnclaveContext<S>,
) -> EnclaveStatus {
    let sig = match Signature::from_bytes(&sig[..]) {
        Ok(sig) => sig,
        Err(_) => {
            debug!("Failed to read signatures.");
            return EnclaveStatus::error();
        }
    };
    let pubkey = match PublicKey::from_bytes(&pubkey[..]) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            debug!("Failed to read public key.");
            return EnclaveStatus::error();
        }
    };
    let key = match UserAddress::from_sig(&challenge[..], &sig, &pubkey) {
        Ok(user_address) => user_address,
        Err(_) => {
            debug!("Failed to generate user address.");
            return EnclaveStatus::error();
        }
    };

    let user_state = &enclave_context.get_state(key, MemId::from_raw(mem_id));
    state.0 = match save_to_host_memory(&user_state.as_bytes()) {
        Ok(ptr) => ptr as *const u8,
        Err(_) => return EnclaveStatus::error(),
    };

    EnclaveStatus::success()
}

pub fn inner_ecall_join_group<S: State>(
    raw_join_group_tx: &mut RawJoinGroupTx,
    enclave_context: EnclaveContext<S>,
    ias_url: &str,
    test_sub_key: &str,
) -> EnclaveStatus {
    let join_group_tx = match JoinGroupTx::construct(
        ias_url,
        test_sub_key,
        &enclave_context,
    ) {
        Ok(join_group_tx) => join_group_tx,
        Err(_) => {
            debug!("Failed to construct JoinGroup transaction.");
            return EnclaveStatus::error();
        }
    };

    *raw_join_group_tx = match join_group_tx.into_raw() {
        Ok(raw) => raw,
        Err(_) => {
            debug!("Failed to convert into raw JoinGroup transaction.");
            return EnclaveStatus::error();
        }
    };

    EnclaveStatus::success()
}

pub fn inner_ecall_instruction<R, C, S>(
    raw_sig: &RawSig,
    raw_pubkey: &RawPubkey,
    raw_challenge: &RawChallenge,
    state: *mut u8,
    state_len: usize,
    state_id: u64,
    call_id: u32,
    raw_instruction_tx: &mut RawInstructionTx,
    enclave_context: EnclaveContext<S>,
    max_mem_size: usize,
) -> EnclaveStatus
where
    R: RuntimeExecutor<C, S>,
    C: ContextOps<S>,
    S: State,
{
    let params = unsafe{ slice::from_raw_parts_mut(state, state_len) };
    let ar = match AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge) {
        Ok(access_right) => access_right,
        Err(_) => {
            debug!("Failed to generate access right.");
            return EnclaveStatus::error();
        }
    };

    let instruction_tx = match InstructionTx::construct::<R, C, S>(
        call_id,
        params,
        state_id,
        &ar,
        &enclave_context,
        max_mem_size,
    ) {
        Ok(instruction_tx) => instruction_tx,
        Err(_) => {
            debug!("Failed to construct state tx.");
            return EnclaveStatus::error();
        }
    };

    enclave_context.set_notification(ar.user_address());
    *raw_instruction_tx = match instruction_tx.into_raw() {
        Ok(raw) => raw,
        Err(_) => {
            debug!("Failed to convert into raw state transaction.");
            return EnclaveStatus::error();
        }
    };

    EnclaveStatus::success()
}

pub fn inner_ecall_handshake<S: State>(
    raw_handshake_tx: &mut RawHandshakeTx,
    enclave_context: EnclaveContext<S>,
) -> EnclaveStatus {
    let handshake_tx = match HandshakeTx::construct(&enclave_context) {
        Ok(handshake_tx) => handshake_tx,
        Err(_) => {
            debug!("Failed to construct handshake transaction.");
            return EnclaveStatus::error();
        }
    };

    *raw_handshake_tx = match handshake_tx.into_raw() {
        Ok(raw) => raw,
        Err(_) => {
            debug!("Failed to convert into raw handshake transaction.");
            return EnclaveStatus::error();
        }
    };

    EnclaveStatus::success()
}

pub fn inner_ecall_register_notification<S: State>(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
    enclave_context: EnclaveContext<S>,
) -> EnclaveStatus {
    let sig = match Signature::from_bytes(&sig[..]) {
        Ok(sig) => sig,
        Err(_) => {
            debug!("Failed to read signatures.");
            return EnclaveStatus::error();
        }
    };
    let pubkey = match PublicKey::from_bytes(&pubkey[..]) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            debug!("Failed to read public key.");
            return EnclaveStatus::error();
        }
    };
    let user_address = match UserAddress::from_sig(&challenge[..], &sig, &pubkey) {
        Ok(user_address) => user_address,
        Err(_) => {
            debug!("Failed to generate user address.");
            return EnclaveStatus::error();
        }
    };

    enclave_context.set_notification(user_address);

    EnclaveStatus::success()
}
