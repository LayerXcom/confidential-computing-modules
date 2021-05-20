use pgx::*;

use crate::host::{encinteger_avg::EncInteger, integer_avg::IntegerAvgState};

use super::{encinteger_decrypt::EncIntegerDecrypt, encinteger_encrypt::EncIntegerEncrypt};

#[pg_extern]
fn encinteger_from(raw_integer: i32) -> EncInteger {
    EncInteger::encrypt(raw_integer)
}

#[pg_extern]
fn encinteger_avg_state_func(
    internal_state: IntegerAvgState,
    next_data_value: EncInteger,
) -> IntegerAvgState {
    let v = next_data_value.decrypt().unwrap();
    internal_state.acc(v)
}

#[pg_extern]
fn encinteger_avg_final_func(internal_state: IntegerAvgState) -> i32 {
    internal_state.finalize()
}
