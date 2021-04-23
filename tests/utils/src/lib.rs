#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
#[macro_use]
extern crate inventory;

#[cfg(feature = "sgx")]
pub use test_utils_proc_macro::test_case;

#[cfg(feature = "std")]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "sgx")]
pub mod runner;
#[cfg(feature = "std")]
pub mod tracing;
