use crate::serde::{Deserialize, Serialize};
use module_encrypted_sql_ops_ecall_types::EncInteger;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub(super) struct EncIntegerWrapper(EncInteger);

impl EcallOutput for EncIntegerWrapper {}
