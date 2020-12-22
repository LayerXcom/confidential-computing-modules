#![no_std]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate inventory;

use serde::{Deserialize, Serialize};
use std::string::String;
use std::vec::Vec;
use std::env;
pub use test_utils_proc_macro::test_case;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct RunTestInput {
    pub test_names: Vec<String>,
}

impl RunTestInput {
    pub fn new(test_names: Vec<String>) -> Self {
        Self { test_names }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RunTestOutput;

pub struct TestCase(pub String, pub fn() -> ());

inventory::collect!(TestCase);

#[macro_export]
macro_rules! run_inventory_tests {
    ($predicate:expr) => {{
        test_utils::test_start();
        let mut ntestcases: u64 = 0u64;
        let mut failurecases: Vec<String> = Vec::new();

        for t in inventory::iter::<test_utils::TestCase>.into_iter() {
            if $predicate(&t.0) {
                test_utils::test(&mut ntestcases, &mut failurecases, t.1, &t.0);
            }
        }

        test_utils::test_end(ntestcases, failurecases)
    }};
    () => {
        run_inventory_tests!(|_| true);
    };
}

#[macro_export]
macro_rules! run_tests {
    (
        $($f:expr),* $(,)?
    ) => {
        {
            test_start();
            let mut ntestcases: u64 = 0u64;
            let mut failurecases: Vec<String> = Vec::new();
            $(test(&mut ntestcases, &mut failurecases, $f, stringify!($f));)*
            test_end(ntestcases, failurecases)
        }
    }
}

#[macro_export]
macro_rules! check_all_passed {
    (
        $($f:expr),* $(,)?
    ) => {
        {
            let mut v: Vec<bool> = Vec::new();
            $(
                v.push($f);
            )*
            v.iter().all(|&x| x)
        }
    }
}

#[macro_export]
macro_rules! should_panic {
    ($fmt:expr) => {{
        match std::panic::catch_unwind(|| $fmt).is_err() {
            true => {
                println!(
                    "{} {} ... {}!",
                    "testing_should_panic",
                    stringify!($fmt),
                    "\x1B[1;32mok\x1B[0m"
                );
            }
            false => std::rt::begin_panic($fmt),
        }
    }};
}

#[allow(clippy::print_literal)]
pub fn test<F, R>(ncases: &mut u64, failurecases: &mut Vec<String>, f: F, name: &str)
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    *ncases += 1;
    let t = || {
        f();
    };
    if std::panic::catch_unwind(t).is_ok() {
        println!("{} {} ... {}!", "testing", name, "\x1B[1;32mok\x1B[0m");
    } else {
        println!("{} {} ... {}!", "testing", name, "\x1B[1;31mfailed\x1B[0m");
        failurecases.push(String::from(name));
    }
}

pub fn test_start() {
    println!("\nstart running tests");
}

pub fn test_end(ntestcases: u64, failurecases: Vec<String>) -> bool {
    let ntotal = ntestcases as usize;
    let nsucc = ntestcases as usize - failurecases.len();

    if !failurecases.is_empty() {
        print!("\nfailures: ");
        println!(
            "    {}",
            failurecases
                .iter()
                .fold(String::new(), |s, per| s + "\n    " + per)
        );
    }

    if ntotal == nsucc {
        print!("\ntest result \x1B[1;32mok\x1B[0m. ");
    } else {
        print!("\ntest result \x1B[1;31mFAILED\x1B[0m. ");
    }

    println!(
        "{} tested, {} passed, {} failed",
        ntotal,
        nsucc,
        ntotal - nsucc
    );
    failurecases.is_empty()
}

pub fn set_env_vars() {
    env::set_var("RUST_LOG", "DEBUG");
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    env::set_var("SPID", "2C149BFC94A61D306A96211AED155BE9");
    env::set_var(
        "IAS_URL",
        "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report",
    );
    env::set_var("SUB_KEY", "77e2533de0624df28dc3be3a5b9e50d9");
    env::set_var("AUDITOR_ENDPOINT", "test");
}
