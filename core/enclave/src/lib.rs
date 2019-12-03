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
use crate::kvs::{MemoryKVS, SigVerificationKVS, MEMORY_DB};
use crate::state::UserState;
use crate::stf::Value;

mod crypto;
mod state;
mod error;
mod kvs;
mod auto_ffi;
mod sealing;
mod stf;
mod attestation;
mod quote;
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

    let db_value = MEMORY_DB.get(&msg[..], &sig, &pubkey).expect("Failed to get value from in-memory database.");
    let user_state = UserState::<Value, _>::get_state_from_db_value(db_value).expect("Failed to read db_value.");
    state = user_state.into_raw_u64();

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_write_state(
    ciphertext: &Ciphertext,
) -> sgx_status_t {

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_state_transition(
    sig: &Sig,
    target: &Address,
    value: u64,
    result: &mut TransitionResult,
) -> sgx_status_t {

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ecall_contract_deploy(
    sig: &Sig,
    value: u64,
    result: &mut TransitionResult,
) -> sgx_status_t {

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
