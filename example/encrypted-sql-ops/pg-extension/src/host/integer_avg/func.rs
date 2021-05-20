use pgx::*;

use super::typ::IntegerAvgState;

#[pg_extern]
fn integer_avg_state_func(
    internal_state: IntegerAvgState,
    next_data_value: i32,
) -> IntegerAvgState {
    internal_state.acc(next_data_value)
}

#[pg_extern]
fn integer_avg_final_func(internal_state: IntegerAvgState) -> i32 {
    internal_state.finalize()
}
