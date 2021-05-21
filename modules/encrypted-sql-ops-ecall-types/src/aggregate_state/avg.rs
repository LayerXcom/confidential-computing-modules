use crate::serde::{Deserialize, Serialize};
/// Intermediate state to calculate average.
///
/// FIXME: Currently `i64` input and `f64` output is only supported.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct AvgState {
    /// current total
    pub sum: i64,

    /// current number of values
    pub n: u64,
}
