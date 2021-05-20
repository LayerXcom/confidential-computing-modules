use pgx::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PostgresType)]
pub struct IntegerAvgState {
    sum: i32,
    n: i32,
}
impl Default for IntegerAvgState {
    fn default() -> Self {
        Self { sum: 0, n: 0 }
    }
}
impl IntegerAvgState {
    pub fn acc(&self, v: i32) -> Self {
        Self {
            sum: self.sum + v,
            n: self.n + 1,
        }
    }
    pub fn finalize(&self) -> i32 {
        self.sum / self.n
    }
}

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use pgx::*;

    use super::IntegerAvgState;

    #[pg_test]
    fn test_integer_avg_state() {
        assert_eq!(
            2,
            IntegerAvgState::default().acc(1).acc(2).acc(3).finalize()
        );
    }
}
