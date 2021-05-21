use pgx::*;

use crate::typ::{AvgState, EncInteger};

#[pg_extern]
fn encinteger_from(raw_integer: i32) -> EncInteger {
    EncInteger::encrypt(raw_integer)
}

#[pg_extern]
fn encinteger_avg_state_func(
    internal_state: AvgState,
    next_data_value: EncInteger,
) -> IntegerAvgState {
    let v = next_data_value.decrypt().unwrap();
    internal_state.acc(v)
}

#[pg_extern]
fn encinteger_avg_final_func(internal_state: IntegerAvgState) -> i32 {
    internal_state.finalize()
}
