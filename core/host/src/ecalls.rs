use sgx_types::*;
use frame_types::EnclaveStatus;
use frame_common::{
    crypto::AccessRight,
    traits::*,
    state_types::UpdatedState,
};
use frame_host::ecalls::EnclaveConnector;
use anonify_common::{
    plugin_types::*,
    commands::*,
};
use crate::{
    eventdb::InnerEnclaveLog,
    utils::StateInfo,
    error::Result,
    workflow::{OUTPUT_MAX_LEN, InsertCiphertextWorkflow, InsertHandshakeWorkflow},
};
use log::debug;
use codec::{Encode, Decode};

pub(crate) fn insert_logs<S: State>(
    eid: sgx_enclave_id_t,
    enclave_log: InnerEnclaveLog,
) -> Result<Option<Vec<UpdatedState<S>>>> {
    if enclave_log.ciphertexts.len() != 0 && enclave_log.handshakes.len() == 0 {
        insert_ciphertexts(eid, enclave_log)
    } else if enclave_log.ciphertexts.len() == 0 && enclave_log.handshakes.len() != 0 {
        // The size of handshake cannot be calculated in this host directory,
        // so the ecall_insert_handshake function is repeatedly called over the number of fetched handshakes.
        for handshake in enclave_log.handshakes {
            insert_handshake(eid, handshake)?;
        }

        Ok(None)
    } else {
        debug!("No logs to insert into the enclave.");
        Ok(None)
    }
}

/// Insert event logs from blockchain nodes into enclave memory database.
fn insert_ciphertexts<S: State>(
    eid: sgx_enclave_id_t,
    enclave_log: InnerEnclaveLog,
) -> Result<Option<Vec<UpdatedState<S>>>> {
    let mut acc = vec![];

    for update in enclave_log
        .into_input_iter()
        .map(move |inp|
            InsertCiphertextWorkflow::exec(inp, eid)
                .map(|e| e.ecall_output.unwrap()) // ecall_output must be set.
        )
    {
        if let Some(upd_type) = update?.updated_state {
            let upd_trait = UpdatedState::<S>::from_state_type(upd_type)?;
            acc.push(upd_trait);
        }
    }

    if acc.is_empty() {
        return Ok(None);
    } else {
        return Ok(Some(acc));
    }
}

fn insert_handshake(
    eid: sgx_enclave_id_t,
    handshake: Vec<u8>,
) -> Result<()> {
    let input = host_input::InsertHandshake::new(handshake);
    InsertHandshakeWorkflow::exec(input, eid)?;

    Ok(())
}
