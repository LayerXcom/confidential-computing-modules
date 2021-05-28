use crate::serde::{Deserialize, Serialize};

/// Intermediate state to calculate average.
///
/// FIXME: Currently `i64` input and `f64` output is only supported.
///
/// FIXME: Internal value should be encrypted (and decrypted in enclave)
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EncAvgState {
    /// current total
    pub sum: i64,

    /// current number of values
    pub n: u64,
}
