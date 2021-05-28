use crate::{
    init::Enclave,
    typ::{EncAvgState, EncInteger},
};
use frame_host::engine::HostEngine;
use module_encrypted_sql_ops_ecall_types::{
    ecall_cmd::*,
    enc_type::{
        enc_aggregate_state::EncAvgState as ModuleEncAvgState, EncInteger as ModuleEncInteger,
    },
};
use module_encrypted_sql_ops_host::workflow::{
    encinteger_from::EncIntegerFromWorkflow,
    host_types::{HostEmpty, HostPlainInteger},
    init_enc_avg_state_func::InitEncAvgStateFuncWorkflow,
};
use pgx::*;

#[pg_extern]
fn encinteger_from(raw_integer: i32) -> EncInteger {
    let host_input = HostPlainInteger::new(raw_integer, ENCINTEGER_FROM);
    let eid = Enclave::global().geteid();

    let host_output = EncIntegerFromWorkflow::exec(host_input, eid).unwrap_or_else(|e| {
        panic!(
            "failed to encrypt raw INTEGER in enclave (Enclave ID: {}), {:?}",
            eid, e
        )
    });

    EncInteger::from(ModuleEncInteger::from(host_output))
}

#[pg_extern]
fn init_enc_avg_state_func() -> EncAvgState {
    let host_input = HostEmpty::new(INIT_ENC_AVG_STATE_FUNC);
    let eid = Enclave::global().geteid();

    let host_output = InitEncAvgStateFuncWorkflow::exec(host_input, eid).unwrap_or_else(|e| {
        panic!(
            "failed to create initial EncAvgState in enclave (Enclave ID: {}), {:?}",
            eid, e
        )
    });

    EncAvgState::from(ModuleEncAvgState::from(host_output))
}

#[pg_extern]
fn encinteger_avg_state_func(
    _internal_state: EncAvgState,
    _next_data_value: EncInteger,
) -> EncAvgState {
    todo!("create Workflow")
}

#[pg_extern]
fn encinteger_avg_final_func(_internal_state: EncAvgState) -> i32 {
    todo!("create Workflow")
}
