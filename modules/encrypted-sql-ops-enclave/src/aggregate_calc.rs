//! Aggregate calculations over aggregate states.

/// TODO: use generics
pub trait AggregateCalc {
    /// Takes a non-NULL value
    fn accumulate(&mut self, val: i32);

    /// Emits an aggregated value
    fn finalize(self) -> f32;
}
