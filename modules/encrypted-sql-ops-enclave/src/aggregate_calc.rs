//! Aggregate calculations over aggregate states.

mod average_calc;

/// TODO: use generics
pub trait AggregateCalc {
    /// Takes a non-NULL value
    fn accumulate(&mut self, val: i64);

    /// Emits an aggregated value
    fn finalize(self) -> f64;
}
