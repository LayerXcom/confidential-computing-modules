use module_encrypted_sql_ops_ecall_types::enc_type::{
    enc_aggregate_state::EncAvgState as ModuleEncAvgState, EncInteger as ModuleEncInteger,
};
use pgx::*;
use serde::{Deserialize, Serialize};

/// `ENCINTEGER` custom SQL type, which is encrypted version of `INTEGER`.
#[derive(Debug, Serialize, Deserialize, PostgresType)]
pub struct EncInteger(ModuleEncInteger);

impl From<ModuleEncInteger> for EncInteger {
    fn from(e: ModuleEncInteger) -> Self {
        Self(e)
    }
}

impl From<EncInteger> for ModuleEncInteger {
    fn from(e: EncInteger) -> Self {
        e.0
    }
}

/// Used as intermediate state on calculating AVG for `ENCINTEGER`.
#[derive(Debug, Serialize, Deserialize, PostgresType)]
pub struct EncAvgState {
    // cannot use enum here to make initial value via `CREATE AGGREGATE`.
    current_state: Option<ModuleEncAvgState>,
}

impl From<ModuleEncAvgState> for EncAvgState {
    fn from(e: ModuleEncAvgState) -> Self {
        Self {
            current_state: Some(e),
        }
    }
}

impl From<EncAvgState> for ModuleEncAvgState {
    fn from(e: EncAvgState) -> Self {
        match e.current_state {
            Some(mod_e) => mod_e,
            None => ModuleEncAvgState::Initial,
        }
    }
}
