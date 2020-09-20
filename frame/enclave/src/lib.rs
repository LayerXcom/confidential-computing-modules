#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

pub mod engine;
mod error;
pub mod ocalls;
mod register;

pub use crate::engine::*;
pub use crate::error::FrameEnclaveError as Error;
