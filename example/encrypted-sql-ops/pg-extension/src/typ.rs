use module_encrypted_sql_ops_ecall_types::{
    enc_type::{EncInteger as ModuleEncInteger, enc_aggregate_state::EncAvgState as ModuleEncAvgState},
};
use pgx::*;
use serde::{Deserialize, Serialize};

/// `ENCINTEGER` custom SQL type, which is encrypted version of `INTEGER`.
#[derive(Serialize, Deserialize, PostgresType)]
pub struct EncInteger(ModuleEncInteger);

impl From<ModuleEncInteger> for EncInteger {
    fn from(e: ModuleEncInteger) -> Self {
        Self(e)
    }
}

/// Used as intermediate state on calculating AVG for `ENCINTEGER`.
#[derive(Serialize, Deserialize, PostgresType)]
pub struct EncAvgState(ModuleEncAvgState);

impl EncAvgState {
    pub(crate) fn into_inner(self) -> ModuleEncAvgState {
        self.0
    }
}
