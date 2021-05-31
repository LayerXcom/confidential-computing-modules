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
    host_types::HostPlainInteger,
    {encinteger_avg_state_func::EncIntegerAvgStateFuncWorkflow, encinteger_from::EncIntegerFromWorkflow},
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
fn encinteger_avg_state_func(
    internal_state: EncAvgState,
    _next_data_value: EncInteger,
) -> EncAvgState {
    // let host_input = HostInputEncAvgState::new(
    //     EnclaveEncAvgState::from(internal_state),
    //     ENCINTEGER_AVG_STATE_FUNC,
    // );
    // let eid = Enclave::global().geteid();

    // let host_output = EncIntegerAvgStateFuncWorkflow::exec(host_input, eid).unwrap_or_else(|e| {
    //     panic!(
    //         "failed to calculate next avg state in enclave (Enclave ID: {}), {:?}",
    //         eid, e
    //     )
    // });

    // EncAvgState::from(ModuleEncAvgState::from(host_output))

    todo!()
}

#[pg_extern]
fn encinteger_avg_final_func(_internal_state: EncAvgState) -> i32 {
    todo!("create Workflow")
}
