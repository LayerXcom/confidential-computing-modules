//! Value Objects and domain services to execute SQL operations / encryption.
//!
//! Everything here is supposed to appear as plain text in RDBMS's process memory space.
//! Take care not to take/pass user inputs in/to this crate.
//!
//! Ideally, everything in this crate serves for any RDBMS's extension development.

#![deny(missing_debug_implementations, missing_docs)]

pub mod enc_type;
