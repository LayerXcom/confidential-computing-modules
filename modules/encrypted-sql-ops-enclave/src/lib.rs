//! Value Objects and domain services to execute SQL operations / encryption.
//!
//! All of them are designed to be only visible in enclave.
//!
//! Ideally, everything in this crate serves for any RDBMS's extension development.

#![deny(missing_debug_implementations, missing_docs)]

pub mod aggregate;
