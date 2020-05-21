pub use anonify_test_utils_proc_macro::test_case;

pub struct TestCase(pub String, pub fn() -> ());

inventory::collect!(TestCase);

#[macro_export]
macro_rules! run_inventory_tests {
     ($predicate:expr) => {{
         // anonify_test_utils::test_start();
         // let mut ntestcases: u64 = 0u64;
         // let mut failurecases: Vec<String> = Vec::new();

         // for t in inventory::iter::<anonify_test_utils::TestCase>.into_iter() {
         for t in inventory::iter::<TestCase>.into_iter() {
             if $predicate(&t.0) {
                 // anonify_test_utils::test(&mut ntestcases, &mut failurecases, t.1, &t.0);
                 test(t.1, &t.0);
             }
         }

         // anonify_test_utils::test_end(ntestcases, failurecases)
     }};
     () => {
         run_inventory_tests!(|_| true);
     };
 }

#[allow(clippy::print_literal)]
pub fn test<F, R>(f: F, name: &str)
// pub fn test<F, R>(ncases: &mut u64, failurecases: &mut Vec<String>, f: F, name: &str)
    where
        F: FnOnce() -> R + std::panic::UnwindSafe,
{
    // *ncases += 1;
    let t = || {
        f();
    };
    if std::panic::catch_unwind(t).is_ok() {
        println!("{} {} ... {}!", "testing", name, "\x1B[1;32mok\x1B[0m");
    } else {
        println!("{} {} ... {}!", "testing", name, "\x1B[1;31mfailed\x1B[0m");
        // failurecases.push(String::from(name));
    }
}
