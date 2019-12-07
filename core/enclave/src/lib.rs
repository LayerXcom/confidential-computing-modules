#![crate_name = "anonifyenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate lazy_static;

use sgx_types::*;
use sgx_tse::*;
use anonify_types::*;
use ed25519_dalek::{PublicKey, Signature};
use crate::kvs::{MemoryKVS, SigVerificationKVS, MEMORY_DB, DBTx};
use crate::state::{UserState, State};
use crate::stf::{Value, AnonymousAssetSTF};
use crate::crypto::{UserAddress, SYMMETRIC_KEY};
use crate::attestation::{
    AttestationService, TEST_SPID, TEST_SUB_KEY,
    DEV_HOSTNAME, REPORT_PATH, IAS_DEFAULT_RETRIES,
};
use crate::quote::EnclaveContext;
use crate::ocalls::save_to_host_memory;

mod crypto;
mod state;
mod error;
mod kvs;
mod auto_ffi;
mod sealing;
mod stf;
mod attestation;
mod quote;
mod ocalls;
#[cfg(debug_assertions)]
mod tests;

//
// ecall
//

#[no_mangle]
pub unsafe extern "C" fn ecall_get_state(
    sig: &Sig,
    pubkey: &PubKey,
    msg: &Msg, // 32 bytes randomness for avoiding replay attacks.
    mut state: u64, // Currently, status is just value.
) -> sgx_status_t {
    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");
    let key = UserAddress::from_sig(&msg[..], &sig, &pubkey);

    let db_value = MEMORY_DB.get(&key).expect("Failed to get value from in-memory database.");
    let user_state = UserState::<Value, _>::from_db_value(db_value).expect("Failed to read db_value.").0;
    state = user_state.into_raw_u64();

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_state_transition(
    sig: &Sig,
    pubkey: &PubKey,
    target: &Address,
    value: u64,
    unsigned_tx: &mut UnsignedTx,
) -> sgx_status_t {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH, IAS_DEFAULT_RETRIES);
    let quote = EnclaveContext::new(TEST_SPID).unwrap().get_quote().unwrap();
    let (report, report_sig) = service.get_report_and_sig(&quote, TEST_SUB_KEY).unwrap();

    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");
    let target_addr = UserAddress::from_array(*target);

    let (my_state, other_state) = UserState::<Value ,_>::transfer(pubkey, sig, target_addr, Value::new(value))
        .expect("Failed to update state.");
    let mut my_ciphertext = my_state.encrypt(&SYMMETRIC_KEY)
        .expect("Failed to encrypt my state.");
    let mut other_ciphertext = other_state.encrypt(&SYMMETRIC_KEY)
        .expect("Failed to encrypt other state.");

    my_ciphertext.append(&mut other_ciphertext);

    unsigned_tx.report = save_to_host_memory(report.as_bytes()).unwrap() as *const u8;
    unsigned_tx.report_sig = save_to_host_memory(report_sig.as_bytes()).unwrap() as *const u8;
    unsigned_tx.ciphertext_num = 2 as u32; // todo;
    unsigned_tx.ciphertexts = save_to_host_memory(&my_ciphertext[..]).unwrap() as *const u8;

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_init_state(
    sig: &Sig,
    pubkey: &PubKey,
    value: u64,
    unsigned_tx: &mut UnsignedTx,
) -> sgx_status_t {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH, IAS_DEFAULT_RETRIES);
    let quote = EnclaveContext::new(TEST_SPID).unwrap().get_quote().unwrap();
    let (report, report_sig) = service.get_report_and_sig(&quote, TEST_SUB_KEY).unwrap();

    let sig = Signature::from_bytes(&sig[..]).expect("Failed to read signatures.");
    let pubkey = PublicKey::from_bytes(&pubkey[..]).expect("Failed to read public key.");

    let total_supply = Value::new(value);
    let init_state = UserState::<Value, _>::init(pubkey, sig, total_supply)
        .expect("Failed to initialize state.");
    let res_ciphertext = init_state.encrypt(&SYMMETRIC_KEY)
        .expect("Failed to encrypt init state.");

    unsigned_tx.report = save_to_host_memory(report.as_bytes()).unwrap() as *const u8;
    unsigned_tx.report_sig = save_to_host_memory(report_sig.as_bytes()).unwrap() as *const u8;
    unsigned_tx.ciphertext_num = 1 as u32; // todo;
    unsigned_tx.ciphertexts = save_to_host_memory(&res_ciphertext[..]).unwrap() as *const u8;

    // // TODO: Allow to compile `Value` to c program.
    // let mut buf = vec![];
    // Value::new(value).write_le(&mut buf).expect("Faild to write value.");

    // let mut dbtx = DBTx::new();
    // dbtx.put(&pubkey, &sig, &buf);
    // MEMORY_DB.write(dbtx);

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
