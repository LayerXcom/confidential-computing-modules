#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

pub mod traits;
mod register;
// mod state_machine;

pub use crate::traits::*;
