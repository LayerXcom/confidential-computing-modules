
#[test]
fn test_in_enclave() {
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let ret = unsafe { ecall_run_tests(
        enclave.geteid(),
    ) };
    assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
}
