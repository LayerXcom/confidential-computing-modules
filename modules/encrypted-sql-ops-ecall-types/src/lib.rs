//! Small sets of data types for communication between host and enclave.
//!
//! Everything here might appear in both enclave and RDBMS's process memory space.
//! Take care not to take/pass user inputs in/to this crate.
//!
//! Ideally, everything in this crate serves for any RDBMS's extension development.

#![deny(missing_debug_implementations, missing_docs)]

pub mod enc_type;
