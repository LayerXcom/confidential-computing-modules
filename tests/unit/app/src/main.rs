use anonify_test_utils::{test_case, run_inventory_tests, RunTestInput, RunTestOutput};
use anyhow::Result;

#[test_case]
fn test_example2() {
    let x = 2;
    assert_eq!(x, 2);
}

#[test_case]
fn test_example_bad() {
    let x = 2;
    assert_eq!(x, 3);
}

fn main() {
    // run tests selectively
    // let input = RunTestInput::new(vec![
    //     "test_example2".to_string(),
    //     "test_example_bad".to_string(),
    // ]);
    // let _ = handle_run_test(&input).unwrap();

    // run all tests
    run_inventory_tests!(|_: &str| true);
}

fn handle_run_test(input: &RunTestInput) -> Result<RunTestOutput> {
    // utils::setup();
    let ret = if input.test_names.is_empty() {
        run_inventory_tests!()
    } else {
        run_inventory_tests!(|s: &str| input.test_names.iter().any(|t| s.contains(t)))
    };

    assert_eq!(ret, true);
    Ok(RunTestOutput)
}
