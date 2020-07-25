#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

pub mod traits;
mod register;
mod error;
mod ocalls;
// mod state_machine;

pub use crate::traits::*;
pub use crate::error::FrameEnclaveError as Error;
