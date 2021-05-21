use super::AggregateCalc;
use module_encrypted_sql_ops_ecall_types::aggregate_state::AvgState;

impl AggregateCalc for AvgState {
    fn accumulate(&mut self, val: i64) {
        self.sum += val;
        self.n += 1;
    }

    fn finalize(self) -> f64 {
        (self.sum as f64) / (self.n as f64)
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
