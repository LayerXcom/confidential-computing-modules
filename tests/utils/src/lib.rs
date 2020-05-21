pub use anonify_test_utils_proc_macro::test_case;

pub struct TestCase(pub String, pub fn() -> ());

inventory::collect!(TestCase);
