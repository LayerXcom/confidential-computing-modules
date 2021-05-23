//! Commands registered via [register_ecall!()](frame-enclave::register_ecall).
//!
//! Has 1-to-1 relationship with SQL function calls.
//! TODO: introduce exit-less mechanism.

#![allow(missing_docs)]

pub const ENCINTEGER_FROM: u32 = 1;
pub const ENCINTEGER_AVG_STATE_FUNC: u32 = 2;
pub const ENCINTEGER_AVG_FINAL_FUNC: u32 = 3;
