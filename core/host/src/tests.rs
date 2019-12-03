use super::*;
use init_enclave::EnclaveDir;
use equote::EnclaveContext;
use anonify_types::{RawPointer, ResultStatus};
use constants::*;
use auto_ffi::ecall_run_tests;
use sgx_types::*;
use attestation::AttestationService;

#[test]
fn test_get_quote() {
    // let enclave = EnclaveDir::new().init_enclave().unwrap();
    // let enclave_context = EnclaveContext::new(enclave.geteid(), &SPID).unwrap();
    // let quote = enclave_context.get_quote().unwrap();
    // println!("quote: {}",  quote.clone());

    // let ias = AttestationService::new(IAS_URL.to_string(), IAS_DEFAULT_RETRIES);
    // let res = ias.get_report(&quote, false).unwrap();



    // enclave.destroy();
}

#[test]
fn test_in_enclave() {
    let mut tmp = 3;
    let enclave = EnclaveDir::new().init_enclave().unwrap();
    let ptr = unsafe { RawPointer::new_mut(&mut tmp) };
    let mut res = ResultStatus::Ok;
    let ret = unsafe { ecall_run_tests(
        enclave.geteid(),
        &ptr as *const RawPointer,
        &mut res,
    ) };

    assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
    assert_eq!(res, ResultStatus::Ok);
}
