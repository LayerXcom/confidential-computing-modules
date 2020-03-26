use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{UserAddress, AccessRight};
use anonify_app_preluder::{CIPHERTEXT_SIZE, Ciphertext, CallKind};
use anonify_runtime::{StateGetter, State, StateType, MemId};
use ed25519_dalek::{PublicKey, Signature};
use crate::state::{UserState, StateValue, Current};
use crate::attestation::{
    TEST_SUB_KEY, DEV_HOSTNAME, REPORT_PATH,
};
use crate::context::ENCLAVE_CONTEXT;
use crate::transaction::{RegisterTx, EnclaveTx, HandshakeTx, StateTransTx};
use crate::kvs::EnclaveDB;
use super::ocalls::save_to_host_memory;

/// Insert event logs from blockchain nodes into enclave's memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_logs(
    _contract_addr: &[u8; 20], //TODO
    _block_number: u64, // TODO
    ciphertexts: *mut u8,
    ciphertexts_len: usize,
) -> sgx_status_t {
    let ciphertexts = slice::from_raw_parts_mut(ciphertexts, ciphertexts_len);
    assert_eq!(ciphertexts.len() % (*CIPHERTEXT_SIZE), 0, "Ciphertexts must be divisible by number of ciphertext.");

    for ciphertext in ciphertexts.chunks_mut(*CIPHERTEXT_SIZE) {
        ENCLAVE_CONTEXT
            .write_cipheriv(Ciphertext::from_bytes(ciphertext), &mut (*ENCLAVE_CONTEXT).group_key())
            .expect("Failed to write cihpertexts.");
    }

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
        .expect("Faild to generate user address.");

    let user_state = &ENCLAVE_CONTEXT.get_by_id(&key, MemId::from_raw(mem_id));
    state.0 = save_to_host_memory(user_state.as_bytes()).unwrap() as *const u8;

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_register(
    raw_register_tx: &mut RawRegisterTx,
) -> sgx_status_t {
    let register_tx = RegisterTx::construct(
            DEV_HOSTNAME,
            REPORT_PATH,
            TEST_SUB_KEY,
            &*ENCLAVE_CONTEXT,
        )
        .expect("Faild to constract register transaction.");

    *raw_register_tx = register_tx.into_raw()
        .expect("Faild to convert into raw register transaction.");

    sgx_status_t::SGX_SUCCESS
}

/// Execute state transition in enclave. It depends on state transition functions and provided inputs.
#[no_mangle]
pub unsafe extern "C" fn ecall_state_transition(
    raw_sig: &RawSig,
    raw_pubkey: &RawPubkey,
    raw_challenge: &RawChallenge,
    state: *mut u8,
    state_len: usize,
    state_id: u64,
    call_id: u32,
    raw_state_tx: &mut RawStateTransTx,
) -> sgx_status_t {
    let params = slice::from_raw_parts_mut(state, state_len);

    let ar = AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge)
        .expect("Failed to generate access right.");
    let call_kind = CallKind::from_call_id(call_id, params)
        .expect("Failed to generate callkind.");
    let state_trans_tx = StateTransTx::construct(
            call_kind,
            state_id,
            &ar,
            &*ENCLAVE_CONTEXT,
        )
        .expect("Failed to construct state tx.");

    *raw_state_tx = state_trans_tx.into_raw()
        .expect("Failed to convert into raw state transaction.");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_handshake(
    raw_handshake_tx: &mut RawHandshakeTx,
) -> sgx_status_t {
    let handshake_tx = HandshakeTx::construct(&*ENCLAVE_CONTEXT)
        .expect("Faild to constract handshake transaction.");

    *raw_handshake_tx = handshake_tx.into_raw()
        .expect("Faild to convert into raw handshake transaction.");

    sgx_status_t::SGX_SUCCESS
}

pub mod enclave_tests {
    use anonify_types::{ResultStatus, RawPointer};

    #[cfg(debug_assertions)]
    mod internal_tests {
        use super::*;
        use sgx_tstd as std;
        use sgx_tunittest::*;
        use std::{panic::UnwindSafe, string::String, vec::Vec};
        use crate::state::tests::*;
        use crate::tests::*;
        use anonify_treekem::tests::*;

        pub unsafe fn internal_tests(ext_ptr: *const RawPointer) -> ResultStatus {
            let mut ctr = 0u64;
            let mut failures = Vec::new();
            rsgx_unit_test_start();

            core_unitests(&mut ctr, &mut failures, test_read_write, "test_read_write");
            core_unitests(&mut ctr, &mut failures, test_get_report, "test_get_report");

            // anonify_treekem
            core_unitests(&mut ctr, &mut failures, app_msg_correctness, "app_msg_correctness");
            core_unitests(&mut ctr, &mut failures, ecies_correctness, "ecies_correctness");

            let result = failures.is_empty();
            rsgx_unit_test_end(ctr, failures);
            result.into()
        }

        fn core_unitests<F, R>(
            ncases: &mut u64,
            failurecases: &mut Vec<String>,
            f: F,
            name: &str
        )
        where
            F: FnOnce() -> R + UnwindSafe
        {
            *ncases = *ncases + 1;
            match std::panic::catch_unwind(|| { f(); }).is_ok()
            {
                true => {
                    println!("{} {} ... {}!", "testing", name, "\x1B[1;32mok\x1B[0m");
                }
                false => {
                    println!("{} {} ... {}!", "testing", name, "\x1B[1;31mfailed\x1B[0m");
                    failurecases.push(String::from(name));
                }
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn ecall_run_tests(ext_ptr: *const RawPointer, result: *mut ResultStatus) {
        *result = ResultStatus::Ok;
        #[cfg(debug_assertions)]
        {
            let internal_tests_result = self::internal_tests::internal_tests(ext_ptr);
            *result = internal_tests_result;
        }
    }
}
