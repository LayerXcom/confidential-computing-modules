/// Intermediate state to calculate average.
///
/// FIXME: Currently `i64` input and `f64` output is only supported.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct AvgState {
    sum: i64,
    n: u64,
}

impl AvgState {
    /// Takes a value as new sample.
    pub fn accumulate(&mut self, val: i64) {
        self.sum += val;
        self.n += 1;
    }

    /// Calculate average for accumulated samples.
    pub fn finalize(self) -> f64 {
        (self.sum as f64) / (self.n as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::AvgState;

    #[test]
    fn test_no_sample() {
        let avg_state = AvgState::default();
        assert!(avg_state.finalize().is_nan());
    }

    #[test]
    fn test_calculation() {
        let mut avg_state = AvgState::default();
        avg_state.accumulate(1);
        avg_state.accumulate(2);
        assert_eq!(avg_state.finalize(), 1.5);
    }
}
