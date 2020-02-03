use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{UserAddress, State, stf::Value};
use ed25519_dalek::{PublicKey, Signature};
use crate::kvs::{EnclaveKVS, MEMORY_DB};
use crate::state::{UserState, StateValue, Current, StfWrapper};
use crate::crypto::{SYMMETRIC_KEY, Ciphertext};
use crate::attestation::{
    AttestationService, TEST_SPID, TEST_SUB_KEY,
    DEV_HOSTNAME, REPORT_PATH,
};
use crate::quote::{EnclaveContext, ENCLAVE_CONTEXT};
use crate::transaction::{RegisterTx, EnclaveTx};
use super::ocalls::save_to_host_memory;

/// Insert event logs from blockchain nodes into enclave's memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_insert_logs(
    _contract_addr: &[u8; 20], //TODO
    _block_number: u64, // TODO
    ciphertexts: *const u8,
    ciphertexts_len: usize, // Byte size of all ciphertexts
    ciphertext_size: usize, // Byte size of a ciphertext
) -> sgx_status_t {
    let ciphertexts = slice::from_raw_parts(ciphertexts, ciphertexts_len);
    assert_eq!(ciphertexts.len() % ciphertext_size, 0, "Ciphertexts must be divisible by ciphertexts_num.");

    for ciphertext in ciphertexts.chunks(ciphertext_size) {
        UserState::<Value ,Current>::insert_cipheriv_memdb(Ciphertext(ciphertext.to_vec()), &SYMMETRIC_KEY)
            .expect("Failed to insert ciphertext into memory database.");
    }

    sgx_status_t::SGX_SUCCESS
}

/// Get current state of the user represented the given public key from enclave memory database.
#[no_mangle]
pub unsafe extern "C" fn ecall_get_state(
    sig: &Sig,
    pubkey: &PubKey,
    msg: &Msg, // 32 bytes randomness for avoiding replay attacks.
    state: &mut EnclaveState,
) -> sgx_status_t {
    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");
    let key = UserAddress::from_sig(&msg[..], &sig, &pubkey);

    let db_value = MEMORY_DB.get(&key);
    let user_state_value = StateValue::<Value, Current>::from_dbvalue(db_value)
        .expect("Failed to read db_value.");
    let user_state = user_state_value.inner_state();

    state.0 = save_to_host_memory(&user_state.as_bytes().unwrap()).unwrap() as *const u8;

    sgx_status_t::SGX_SUCCESS
}

/// Execute state transition in enclave. It depends on state transition functions and provided inputs.
#[no_mangle]
pub unsafe extern "C" fn ecall_state_transition(
    sig: &Sig,
    pubkey: &PubKey,
    msg: &Msg,
    target: &Address,
    state: *const u8,
    state_len: usize,
    unsigned_tx: &mut RawUnsignedTx,
) -> sgx_status_t {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH);
    let quote = EnclaveContext::new(TEST_SPID).unwrap().get_quote().unwrap();
    let (report, report_sig) = service.get_report_and_sig(&quote, TEST_SUB_KEY).unwrap();

    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");
    let target_addr = UserAddress::from_array(*target);
    let params = slice::from_raw_parts(state, state_len);
    let params = Value::from_bytes(&params).unwrap();

    let (ciphertexts, ciphertext_num) = StfWrapper::new(pubkey, sig, &msg[..], target_addr)
        .apply::<Value>("transfer", params, &SYMMETRIC_KEY)
        .expect("Faild to execute applying function.");

    unsigned_tx.report = save_to_host_memory(&report[..]).unwrap() as *const u8;
    unsigned_tx.report_sig = save_to_host_memory(&report_sig[..]).unwrap() as *const u8;
    unsigned_tx.ciphertext_num = ciphertext_num; // todo;
    unsigned_tx.ciphertexts = save_to_host_memory(&ciphertexts[..]).unwrap() as *const u8;

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
    sig: &Sig,
    pubkey: &PubKey,
    msg: &Msg,
    state: *const u8,
    state_len: usize,
    unsigned_tx: &mut RawUnsignedTx,
) -> sgx_status_t {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH);
    let quote = EnclaveContext::new(TEST_SPID).unwrap().get_quote().unwrap();
    let (report, report_sig) = service.get_report_and_sig(&quote, TEST_SUB_KEY).unwrap();

    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");

    let params = slice::from_raw_parts(state, state_len);
    let params = Value::from_bytes(&params).unwrap();

    let user_address = UserAddress::from_sig(&msg[..], &sig, &pubkey);
    let init_state = UserState::<Value, _>::init(user_address, params)
        .expect("Failed to initialize state.");
    let res_ciphertext = init_state.encrypt(&SYMMETRIC_KEY)
        .expect("Failed to encrypt init state.");

    unsigned_tx.report = save_to_host_memory(&report[..]).unwrap() as *const u8;
    unsigned_tx.report_sig = save_to_host_memory(&report_sig[..]).unwrap() as *const u8;
    unsigned_tx.ciphertext_num = 1;
    unsigned_tx.ciphertexts = save_to_host_memory(&res_ciphertext.0[..]).unwrap() as *const u8;

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
