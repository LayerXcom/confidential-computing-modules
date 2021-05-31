use module_encrypted_sql_ops_ecall_types::enc_type::{
    enc_aggregate_state::EncAvgState as ModuleEncAvgState, EncInteger as ModuleEncInteger,
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
pub struct EncAvgState {
    current_state: Option<ModuleEncAvgState>,
}

impl EncAvgState {
    pub(crate) fn into_inner(self) -> ModuleEncAvgState {
        self.current_state.expect("should be already initialized")
    }
}

impl From<ModuleEncAvgState> for EncAvgState {
    fn from(e: ModuleEncAvgState) -> Self {
        Self {
            current_state: Some(e),
        }
    }
}
