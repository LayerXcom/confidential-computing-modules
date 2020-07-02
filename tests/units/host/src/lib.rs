use sgx_types::{sgx_status_t, sgx_enclave_id_t};
use anonify_host::init_enclave::EnclaveDir;

extern "C" {
    pub fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t;
}

#[test]
fn test_in_enclave() {
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let ret = unsafe { ecall_run_tests(
        enclave.geteid(),
    ) };

    assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
}
