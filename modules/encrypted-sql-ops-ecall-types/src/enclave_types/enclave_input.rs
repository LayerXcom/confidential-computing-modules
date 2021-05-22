use crate::serde::{Deserialize, Serialize};
use frame_common::EcallInput;

/// Input to enclave
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct RawInteger(i32);

impl EcallInput for RawInteger {}

impl From<i32> for RawInteger {
    fn from(integer: i32) -> Self {
        Self(integer)
    }
}
