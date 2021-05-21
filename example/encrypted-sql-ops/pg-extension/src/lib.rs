//! Anti-corruption layer facing pgx.
//! All user-defined functions, types, operations, and aggregates are defined here.
//!
//! This crate should not include any substantial logics.

#![deny(missing_debug_implementations, missing_docs)]

mod aggregate;
mod func;
mod typ;

use pgx::*;

pg_module_magic!();

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
