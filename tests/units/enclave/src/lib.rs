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
