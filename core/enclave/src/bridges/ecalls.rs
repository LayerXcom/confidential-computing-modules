use std::vec::Vec;
use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{UserAddress, State, stf::Value, kvs::MemoryDB, Ciphertext, CIPHERTEXT_SIZE, AccessRight};
use ed25519_dalek::{PublicKey, Signature};
use crate::kvs::EnclaveDB;
use crate::state::{UserState, StateValue, Current};
use crate::crypto::SYMMETRIC_KEY;
use crate::attestation::{
    AttestationService, TEST_SPID, TEST_SUB_KEY,
    DEV_HOSTNAME, REPORT_PATH,
};
use crate::context::{EnclaveContext, ENCLAVE_CONTEXT};
use crate::transaction::{RegisterTx, InitStateTx, EnclaveTx, StateTransTx};
use super::ocalls::save_to_host_memory;

/// Insert event logs from blockchain nodes into enclave's memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_logs(
    _contract_addr: &[u8; 20], //TODO
    _block_number: u64, // TODO
    ciphertexts: *const u8,
    ciphertexts_len: usize,
) -> sgx_status_t {
    let ciphertexts = slice::from_raw_parts(ciphertexts, ciphertexts_len);
    assert_eq!(ciphertexts.len() % CIPHERTEXT_SIZE, 0, "Ciphertexts must be divisible by ciphertexts_num.");

    for ciphertext in ciphertexts.chunks(CIPHERTEXT_SIZE) {
        UserState::<Value, Current>::insert_cipheriv_memdb::<MemoryDB>(
            Ciphertext::from_bytes(ciphertext), &SYMMETRIC_KEY, &*ENCLAVE_CONTEXT,
        )
        .expect("Failed to insert ciphertext into memory database.");
    }

    sgx_status_t::SGX_SUCCESS
}

/// Get current state of the user represented the given public key from enclave memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_get_state(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge, // 32 bytes randomness for avoiding replay attacks.
    state: &mut EnclaveState,
) -> sgx_status_t {
    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");
    let key = UserAddress::from_sig(&challenge[..], &sig, &pubkey).expect("Faild to generate user address.");

    let db_value = ENCLAVE_CONTEXT.get(&key);
    let user_state_value = StateValue::<Value, Current>::from_dbvalue(db_value)
        .expect("Failed to read db_value.");
    let user_state = user_state_value.inner_state();

    state.0 = save_to_host_memory(&user_state.as_bytes().unwrap()).unwrap() as *const u8;

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_register(
    raw_register_tx: &mut RawRegisterTx,
) -> sgx_status_t {
    let register_tx = RegisterTx::construct(DEV_HOSTNAME, REPORT_PATH, TEST_SUB_KEY, &ENCLAVE_CONTEXT)
        .expect("Faild to constract register transaction.");
    *raw_register_tx = register_tx.into_raw()
        .expect("Faild to convert into raw register transaction.");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_init_state(
    raw_sig: &RawSig,
    raw_pubkey: &RawPubkey,
    raw_challenge: &RawChallenge,
    state: *const u8,
    state_len: usize,
    state_id: u64,
    raw_state_tx: &mut RawStateTransTx,
) -> sgx_status_t {
    let ar = AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge).expect("Failed to generate access right.");
    let user_address = UserAddress::from_access_right(&ar)
        .expect("Failed to generate user address from access right.");
    let params = slice::from_raw_parts(state, state_len);

    let init_state_tx = InitStateTx::construct::<Value, _>(state_id, params, user_address, &ENCLAVE_CONTEXT)
        .expect("Failed to construct init state tx.");
    *raw_state_tx = init_state_tx.into_raw()
        .expect("Failed to convert into raw init state transaction.");

    sgx_status_t::SGX_SUCCESS
}

/// Execute state transition in enclave. It depends on state transition functions and provided inputs.
#[no_mangle]
pub unsafe extern "C" fn ecall_state_transition(
    raw_pubkey: &RawPubkey,
    raw_sig: &RawSig,
    raw_challenge: &RawChallenge,
    target: &Address,
    state: *const u8,
    state_len: usize,
    state_id: u64,
    raw_state_tx: &mut RawStateTransTx,
) -> sgx_status_t {
    let target_addr = UserAddress::from_array(*target);
    let params = slice::from_raw_parts(state, state_len);

    let ar = AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge).expect("Failed to generate access right.");
    let state_trans_tx = StateTransTx::construct::<Value, _>(
        state_id, params, &ar, target_addr, &ENCLAVE_CONTEXT
    )
        .expect("Failed to construct init state tx.");
    *raw_state_tx = state_trans_tx.into_raw()
        .expect("Failed to convert into raw init state transaction.");

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

        pub unsafe fn internal_tests(ext_ptr: *const RawPointer) -> ResultStatus {
            let mut ctr = 0u64;
            let mut failures = Vec::new();
            rsgx_unit_test_start();

            core_unitests(&mut ctr, &mut failures, test_read_write, "test_read_write");
            core_unitests(&mut ctr, &mut failures, test_get_report, "test_get_report");

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
