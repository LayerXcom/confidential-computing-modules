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
    host_types::{HostEncAvgStateWithNext, HostInputEncAvgState, HostPlainInteger},
    {
        encinteger_avg_final_func::EncIntegerAvgFinalFuncWorkflow,
        encinteger_avg_state_func::EncIntegerAvgStateFuncWorkflow,
        encinteger_from::EncIntegerFromWorkflow,
    },
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
    next_data_value: EncInteger,
) -> EncAvgState {
    let host_input = HostEncAvgStateWithNext::new(
        ModuleEncAvgState::from(internal_state),
        ModuleEncInteger::from(next_data_value),
        ENCINTEGER_AVG_STATE_FUNC,
    );
    let eid = Enclave::global().geteid();

    let host_output = EncIntegerAvgStateFuncWorkflow::exec(host_input, eid).unwrap_or_else(|e| {
        panic!(
            "failed to calculate next avg state in enclave (Enclave ID: {}), {:?}",
            eid, e
        )
    });

    ModuleEncAvgState::from(host_output).into()
}

#[pg_extern]
fn encinteger_avg_final_func(internal_state: EncAvgState) -> f32 {
    let host_input = HostInputEncAvgState::new(
        ModuleEncAvgState::from(internal_state),
        ENCINTEGER_AVG_FINAL_FUNC,
    );
    let eid = Enclave::global().geteid();

    EncIntegerAvgFinalFuncWorkflow::exec(host_input, eid)
        .unwrap_or_else(|e| {
            panic!(
                "failed to finalize avg state in enclave (Enclave ID: {}), {:?}",
                eid, e
            )
        })
        .into()
}
