use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{UserAddress, AccessRight, Ciphertext};
use anonify_runtime::{StateGetter, MemId, StateType};
use anonify_treekem::handshake::HandshakeParams;
use ed25519_dalek::{PublicKey, Signature};
use codec::Decode;
use anonify_enclave::{
    transaction::{JoinGroupTx, EnclaveTx, HandshakeTx, InstructionTx},
    config::{IAS_URL, TEST_SUB_KEY},
    instructions::Instructions,
    notify::updated_state_into_raw,
    bridges::ocalls::save_to_host_memory,
    context::EnclaveContext,
};
use crate::ENCLAVE_CONTEXT;
use crate::logics::{CIPHERTEXT_SIZE, MAX_MEM_SIZE, Runtime};

type Context = EnclaveContext<StateType>;

/// Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_ciphertext(
    ciphertext: *mut u8,
    ciphertext_len: usize,
    raw_updated_state: &mut RawUpdatedState,
) -> sgx_status_t {
    let buf = slice::from_raw_parts_mut(ciphertext, ciphertext_len);
    let ciphertext = Ciphertext::from_bytes(buf, CIPHERTEXT_SIZE);
    let group_key = &mut *ENCLAVE_CONTEXT.group_key.write().unwrap();

    if let Some(updated_state_iter) =
        Instructions::<Runtime<Context>, Context>::state_transition(ENCLAVE_CONTEXT.clone(), &ciphertext, group_key).unwrap() {
            if let Some(updated_state) = ENCLAVE_CONTEXT.update_state(updated_state_iter) {
                *raw_updated_state = updated_state_into_raw(updated_state)
                    .expect("Failed to convert into raw updated state");
            }
        }

    let roster_idx = ciphertext.roster_idx() as usize;
    // ratchet app keychain per a log.
    group_key.ratchet(roster_idx).unwrap();

    sgx_status_t::SGX_SUCCESS
}

/// Insert handshake received from blockchain nodes into enclave.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_handshake(
    handshake: *mut u8,
    handshake_len: usize,
) -> sgx_status_t {
    let handshake_bytes = slice::from_raw_parts_mut(handshake, handshake_len);
    let handshake = HandshakeParams::decode(&mut &handshake_bytes[..]).unwrap();
    let group_key = &mut *ENCLAVE_CONTEXT.group_key.write().unwrap();

    group_key.process_handshake(&handshake).unwrap();

    sgx_status_t::SGX_SUCCESS
}

/// Get current state of the user represented the given public key from enclave memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_get_state(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge, // 32 bytes randomness for avoiding replay attacks.
    mem_id: u32,
    state: &mut EnclaveState,
) -> sgx_status_t {
    let sig = Signature::from_bytes(&sig[..])
        .expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..])
        .expect("Failed to read public key.");
    let key = UserAddress::from_sig(&challenge[..], &sig, &pubkey)
        .expect("Failed to generate user address.");

    let user_state = &ENCLAVE_CONTEXT.get::<StateType, _>(key, MemId::from_raw(mem_id)).unwrap();
    state.0 = save_to_host_memory(user_state.as_bytes()).unwrap() as *const u8;

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_join_group(
    raw_join_group_tx: &mut RawJoinGroupTx,
) -> sgx_status_t {
    let join_group_tx = JoinGroupTx::construct(
            IAS_URL,
            TEST_SUB_KEY,
            &*ENCLAVE_CONTEXT,
        )
        .expect("Failed to construct JoinGroup transaction.");

    *raw_join_group_tx = join_group_tx.into_raw()
        .expect("Failed to convert into raw JoinGroup transaction.");

    sgx_status_t::SGX_SUCCESS
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
) -> sgx_status_t {
    let params = slice::from_raw_parts_mut(state, state_len);
    let ar = AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge)
        .expect("Failed to generate access right.");

    let instruction_tx = InstructionTx::construct::<Runtime<Context>, Context>(
            call_id,
            params,
            state_id,
            &ar,
            &*ENCLAVE_CONTEXT,
            MAX_MEM_SIZE,
        )
        .expect("Failed to construct state tx.");

    ENCLAVE_CONTEXT.set_notification(ar.user_address());
    *raw_instruction_tx = instruction_tx.into_raw()
        .expect("Failed to convert into raw state transaction.");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_handshake(
    raw_handshake_tx: &mut RawHandshakeTx,
) -> sgx_status_t {
    let handshake_tx = HandshakeTx::construct(&*ENCLAVE_CONTEXT)
        .expect("Failed to construct handshake transaction.");

    *raw_handshake_tx = handshake_tx.into_raw()
        .expect("Failed to convert into raw handshake transaction.");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_register_notification(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
) -> sgx_status_t {
    let sig = Signature::from_bytes(&sig[..])
        .expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..])
        .expect("Failed to read public key.");
    let user_address = UserAddress::from_sig(&challenge[..], &sig, &pubkey)
        .expect("Failed to generate user address.");

    ENCLAVE_CONTEXT.set_notification(user_address);

    sgx_status_t::SGX_SUCCESS
}

#[cfg(debug_assertions)]
pub mod enclave_tests {
    use test_utils::{test_case, run_inventory_tests};
    use std::vec::Vec;
    use std::string::{String, ToString};

    #[test_case]
    fn test_app_msg_correctness() {
        anonify_treekem::tests::app_msg_correctness();
    }

    #[test_case]
    fn test_ecies_correctness() { anonify_treekem::tests::ecies_correctness(); }

    #[no_mangle]
    pub fn ecall_run_tests() { run_inventory_tests!(|_s: &str| true); }
}
