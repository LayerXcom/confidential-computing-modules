//! Anti-corruption layer facing pgx.
//! All user-defined functions, types, operations, and aggregates are defined here.
//!
//! This crate should not include any substantial logics.

#![deny(missing_debug_implementations)]

mod aggregate;
mod func;
mod init;
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

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use pgx::*;

    fn prepare() {
        Spi::run("CREATE TABLE t (id INTEGER, c_enc ENCINTEGER)");
        Spi::run("INSERT INTO t (id, c_enc) VALUES (1, ENCINTEGER_FROM(1)), (2, ENCINTEGER_FROM(2)), (3, ENCINTEGER_FROM(3)), (4, ENCINTEGER_FROM(4))");
    }

    fn encinteger_avg() -> f32 {
        Spi::get_one::<f32>("SELECT AVG(c_enc) FROM t;").unwrap()
    }

    fn encinteger_avg_empty() -> f32 {
        Spi::get_one::<f32>("SELECT AVG(c_enc) FROM t WHERE id > 4;").unwrap()
    }

    #[pg_test]
    fn test_encinteger_avg() {
        prepare();
        assert_eq!(encinteger_avg(), 2.5);
        assert!(encinteger_avg_empty().is_nan());
    }
}
