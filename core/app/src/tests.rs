use super::*;
use init_enclave::EnclaveDir;

#[test]
fn test_get_quote() {
    let enclave = EnclaveDir::new().init_enclave().unwrap();
}
