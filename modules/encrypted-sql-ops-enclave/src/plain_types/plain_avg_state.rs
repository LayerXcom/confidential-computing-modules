use crate::aggregate_calc::AggregateCalc;

use super::PlainI32;

/// Intermediate state to calculate average.
///
/// FIXME: Currently `i32` input and `f32` output is only supported.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PlainAvgState {
    /// current total
    pub sum: PlainI32,

    /// current number of values
    pub n: PlainI32,
}

impl AggregateCalc for PlainAvgState {
    fn accumulate(&mut self, val: i32) {
        self.sum = PlainI32::new(self.sum.to_i32() + val);
        self.n = PlainI32::new(self.n.to_i32() + 1);
    }

    fn finalize(self) -> f32 {
        (self.sum.to_i32() as f32) / (self.n.to_i32() as f32)
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregate_calc::AggregateCalc;
    use module_encrypted_sql_ops_ecall_types::aggregate_state::AvgState;

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
