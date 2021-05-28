/// Intermediate state to calculate average.
///
/// FIXME: Currently `i64` input and `f64` output is only supported.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PlainAvgState {
    /// current total
    pub sum: i64,

    /// current number of values
    pub n: u64,
}
