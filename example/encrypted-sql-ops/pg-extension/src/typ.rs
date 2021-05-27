use module_encrypted_sql_ops_ecall_types::{
    aggregate_state::AvgState as ModuleAvgState, enc_type::EncInteger as ModuleEncInteger,
};
use pgx::*;
use serde::{Deserialize, Serialize};

/// `ENCINTEGER` custom SQL type, which is encrypted version of `INTEGER`.
#[derive(Serialize, Deserialize, PostgresType)]
pub struct EncInteger(ModuleEncInteger);

/// Used as intermediate state on calculating AVG for `ENCINTEGER`.
#[derive(Serialize, Deserialize, PostgresType)]
pub struct AvgState(ModuleAvgState);

impl From<ModuleEncInteger> for EncInteger {
    fn from(e: ModuleEncInteger) -> Self {
        Self(e)
    }
}