use crate::typ::{AvgState, EncInteger};
use frame_host::engine::HostEngine;
use module_encrypted_sql_ops_ecall_types::{
    ecall_cmd::ENCINTEGER_FROM, enc_type::EncInteger as ModuleEncInteger,
};
use module_encrypted_sql_ops_host::workflow::{host_input::RawInteger, EncIntegerFromWorkflow};
use pgx::*;

#[pg_extern]
fn encinteger_from(raw_integer: i32) -> EncInteger {
    let eid = unsafe { crate::init::EID };
    let host_input = RawInteger::new(raw_integer, ENCINTEGER_FROM);

    let host_output = EncIntegerFromWorkflow::exec(host_input, eid)
        .expect("failed to encrypt raw INTEGER in enclave");

    EncInteger::from(ModuleEncInteger::from(host_output))
}

#[pg_extern]
fn encinteger_avg_state_func(_internal_state: AvgState, _next_data_value: EncInteger) -> AvgState {
    todo!("create Workflow")
}

#[pg_extern]
fn encinteger_avg_final_func(_internal_state: AvgState) -> i32 {
    todo!("create Workflow")
}
