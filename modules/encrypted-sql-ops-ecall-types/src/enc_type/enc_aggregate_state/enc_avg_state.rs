use crate::serde::{Deserialize, Serialize};
use std::vec::Vec;

/// Intermediate state to calculate average (Encrypted).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EncAvgState(Vec<u8>);
