use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{
    crypto::{UserAddress, AccessRight, Ciphertext},
    state_types::{MemId, StateType},
};
use anonify_runtime::traits::*;
use anonify_treekem::handshake::HandshakeParams;
use ed25519_dalek::{PublicKey, Signature};
use codec::Decode;
use log::debug;
use anonify_enclave::{
    transaction::{JoinGroupTx, EnclaveTx, HandshakeTx, InstructionTx},
    config::{IAS_URL, TEST_SUB_KEY},
    instructions::Instructions,
    notify::updated_state_into_raw,
    bridges::ocalls::save_to_host_memory,
    context::EnclaveContext,
};
use erc20_state_transition::{CIPHERTEXT_SIZE, MAX_MEM_SIZE, Runtime};
use crate::ENCLAVE_CONTEXT;
use anonify_enclave::bridges::inner_ecalls::*;

type Context = EnclaveContext<StateType>;

/// Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_ciphertext(
    ciphertext: *mut u8,
    ciphertext_len: usize,
    raw_updated_state: &mut RawUpdatedState,
) -> EnclaveStatus {
    inner_ecall_insert_ciphertext::<_,EnclaveContext::<StateType>>(
        ciphertext,
        ciphertext_len,
        raw_updated_state,
        CIPHERTEXT_SIZE,
        *ENCLAVE_CONTEXT
    )
    // let buf = slice::from_raw_parts_mut(ciphertext, ciphertext_len);
    // let ciphertext = Ciphertext::from_bytes(buf, CIPHERTEXT_SIZE);
    // let group_key = &mut *match ENCLAVE_CONTEXT.group_key.write() {
    //     Ok(group_key) => group_key,
    //     Err(_) => return EnclaveStatus::error(),
    // };

    // // match Instructions::<Runtime<Context, StateType>, Context, StateType>::state_transition(ENCLAVE_CONTEXT.clone(), &ciphertext, group_key) {
    // match Instructions::<_,_,StateType>::state_transition(ENCLAVE_CONTEXT.clone(), &ciphertext, group_key) {
    //     Ok(iter_op) => {
    //         if let Some(updated_state_iter) = iter_op {
    //             if let Some(updated_state) = ENCLAVE_CONTEXT.update_state(updated_state_iter) {
    //                 match updated_state_into_raw(updated_state) {
    //                     Ok(new) => *raw_updated_state = new,
    //                     Err(_) => {
    //                         debug!("Failed updated_state_into_raw(updated_state)");
    //                         return EnclaveStatus::error();
    //                     }
    //                 }
    //             }
    //         }
    //     },
    //     Err(_) => {
    //         debug!("Failed Instructions::state_transition");
    //         return EnclaveStatus::error();
    //     },
    // }

    // let roster_idx = ciphertext.roster_idx() as usize;
    // // ratchet app keychain per a log.
    // if group_key.ratchet(roster_idx).is_err() {
    //     return EnclaveStatus::error();
    // }

    // EnclaveStatus::success()
}

/// Insert handshake received from blockchain nodes into enclave.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_handshake(
    handshake: *mut u8,
    handshake_len: usize,
) -> EnclaveStatus {
    let handshake_bytes = slice::from_raw_parts_mut(handshake, handshake_len);
    let handshake = match HandshakeParams::decode(&mut &handshake_bytes[..]) {
        Ok(handshake) => handshake,
        Err(_) => return EnclaveStatus::error(),
    };
    let group_key = &mut *match ENCLAVE_CONTEXT.group_key.write() {
        Ok(group_key) => group_key,
        Err(_) => return EnclaveStatus::error(),
    };

    if group_key.process_handshake(&handshake).is_err() {
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

    let user_state = &*ENCLAVE_CONTEXT.get_type(key, MemId::from_raw(mem_id));
    state.0 = match save_to_host_memory(user_state.as_bytes()) {
        Ok(ptr) => ptr as *const u8,
        Err(_) => return EnclaveStatus::error(),
    };

    EnclaveStatus::success()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_join_group(
    raw_join_group_tx: &mut RawJoinGroupTx,
) -> EnclaveStatus {
    let join_group_tx = match JoinGroupTx::construct(
        IAS_URL,
        TEST_SUB_KEY,
        &*ENCLAVE_CONTEXT,
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
    let params = slice::from_raw_parts_mut(state, state_len);
    let ar = match AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge) {
        Ok(access_right) => access_right,
        Err(_) => {
            debug!("Failed to generate access right.");
            return EnclaveStatus::error();
        }
    };

    let instruction_tx = match InstructionTx::construct::<Runtime<Context>, Context>(
        call_id,
        params,
        state_id,
        &ar,
        &*ENCLAVE_CONTEXT,
        MAX_MEM_SIZE,
    ) {
        Ok(instruction_tx) => instruction_tx,
        Err(_) => {
            debug!("Failed to construct state tx.");
            return EnclaveStatus::error();
        }
    };

    ENCLAVE_CONTEXT.set_notification(ar.user_address());
    *raw_instruction_tx = match instruction_tx.into_raw() {
        Ok(raw) => raw,
        Err(_) => {
            debug!("Failed to convert into raw state transaction.");
            return EnclaveStatus::error();
        }
    };

    EnclaveStatus::success()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_handshake(
    raw_handshake_tx: &mut RawHandshakeTx,
) -> EnclaveStatus {
    let handshake_tx = match HandshakeTx::construct(&*ENCLAVE_CONTEXT) {
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

#[no_mangle]
pub unsafe extern "C" fn ecall_register_notification(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
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

    ENCLAVE_CONTEXT.set_notification(user_address);

    EnclaveStatus::success()
}
