use anonify_test_utils::run_inventory_tests;

fn main() {
    // run all tests
    run_inventory_tests!(|_: &str| true);
}
