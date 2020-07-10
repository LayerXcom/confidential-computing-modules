use sgx_types::*;
use anonify_types::{traits::SliceCPtr, EnclaveState, RawJoinGroupTx, RawInstructionTx, RawHandshakeTx, RawUpdatedState, EnclaveStatus};
use anonify_common::{
    crypto::AccessRight,
    traits::*,
    state_types::UpdatedState,
};
use anonify_bc_connector::{
    eventdb::InnerEnclaveLog,
    utils::StateInfo,
    error::{HostError, Result},
};
use log::debug;
use crate::auto_ffi::*;

pub struct EnclaveConnector{
    eid: sgx_enclave_id_t,
    output_max_len: usize,
}

impl EnclaveConnector {
    pub fn new(eid: sgx_enclave_id_t, output_max_len: usize) -> Self {
        EnclaveConnector {
            eid,
            output_max_len,
        }
    }

    pub fn invoke_ecall(&self, cmd: u32, input: S) -> Result<D>
    where
        S: serde::Serialize,
        D: for<'de> serde::Deserialize<'de>
    {
        let input_payload = serde_json::to_vec(&input)?;
        let result = self.inner_invoke_ecall(cmd, input_payload)?;
        let response: D = serde_json::from_slice(&result)?;

        Ok(response)
    }

    fn inner_invoke_ecall(&self, cmd: u32, input: Vec<u8>) -> Result<Vec<u8>> {
        unimplemented!();
    }
}



pub(crate) fn encrypt_instruction<S, C>(
    eid: sgx_enclave_id_t,
    access_right: AccessRight,
    state_info: StateInfo<'_, S, C>,
) -> Result<RawInstructionTx>
where
    S: State,
    C: CallNameConverter,
{
    let mut rt = EnclaveStatus::default();
    let mut raw_instruction_tx = RawInstructionTx::default();
    let state = state_info.state_encode();
    let call_id = state_info.call_name_to_id();

    let status = unsafe {
        ecall_instruction(
            eid,
            &mut rt,
            access_right.sig().to_bytes().as_ptr() as _,
            access_right.pubkey().to_bytes().as_ptr() as _,
            access_right.challenge().as_ptr() as _,
            state.as_c_ptr() as *mut u8,
            state.len(),
            state_info.state_id(),
            call_id,
            &mut raw_instruction_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx { status, function: "ecall_encrypt_instruction" }.into());
    }
    if rt.is_err() {
        return Err(HostError::Enclave { status: rt, function: "ecall_encrypt_instruction" }.into());
    }

    Ok(raw_instruction_tx)
}

pub(crate) fn insert_logs<S: State>(
    eid: sgx_enclave_id_t,
    enclave_log: &InnerEnclaveLog,
    ciphertext_size: usize,
) -> Result<Option<Vec<UpdatedState<S>>>> {
    if enclave_log.ciphertexts.len() != 0 && enclave_log.handshakes.len() == 0 {
        insert_ciphertexts(eid, &enclave_log, ciphertext_size)
    } else if enclave_log.ciphertexts.len() == 0 && enclave_log.handshakes.len() != 0 {
        // The size of handshake cannot be calculated in this host directory,
        // so the ecall_insert_handshake function is repeatedly called over the number of fetched handshakes.
        for handshake in &enclave_log.handshakes {
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
    enclave_log: &InnerEnclaveLog,
    ciphertext_size: usize,
) -> Result<Option<Vec<UpdatedState<S>>>> {
    let mut rt = EnclaveStatus::default();
    let mut acc = vec![];

    for ciphertext in &enclave_log.ciphertexts {
        let mut raw_updated_state = RawUpdatedState::default();
        let status = unsafe {
            ecall_insert_ciphertext(
                eid,
                &mut rt,
                ciphertext.into_vec().as_c_ptr() as *mut u8,
                ciphertext_size,
                &mut raw_updated_state,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(HostError::Sgx { status, function: "ecall_insert_ciphertext" }.into());
        }
        if rt.is_err() {
            return Err(HostError::Enclave { status: rt, function: "ecall_insert_ciphertext" }.into());
        }

        if raw_updated_state != Default::default() {
            let updated_state = UpdatedState::from(raw_updated_state);
            acc.push(updated_state)
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
    handshake: &[u8],
) -> Result<()> {
    let mut rt = EnclaveStatus::default();

    let status = unsafe {
        ecall_insert_handshake(
            eid,
            &mut rt,
            handshake.as_c_ptr() as *mut u8,
            handshake.len(),
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx { status, function: "ecall_insert_handshake" }.into());
    }
    if rt.is_err() {
        return Err(HostError::Enclave { status: rt, function: "ecall_insert_handshake" }.into());
    }

    Ok(())
}

/// Get state only if the signature verification returns true.
pub(crate) fn get_state_from_enclave<M: MemNameConverter>(
    eid: sgx_enclave_id_t,
    access_right: &AccessRight,
    mem_name: &str,
) -> Result<Vec<u8>>
{
    let mut rt = EnclaveStatus::default();
    let mut state = EnclaveState::default();
    let mem_id = M::as_id(mem_name).as_raw();

    let status = unsafe {
        ecall_get_state(
            eid,
            &mut rt,
            access_right.sig().to_bytes().as_ptr() as _,
            access_right.pubkey().to_bytes().as_ptr() as _,
            access_right.challenge().as_ptr() as _,
            mem_id,
            &mut state,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx { status, function: "ecall_get_state" }.into());
    }
    if rt.is_err() {
        return Err(HostError::Enclave { status: rt, function: "ecall_get_state" }.into());
    }

    Ok(state.into_vec())
}

pub(crate) fn join_group(eid: sgx_enclave_id_t) -> Result<RawJoinGroupTx> {
    let mut rt = EnclaveStatus::default();
    let mut raw_reg_tx = RawJoinGroupTx::default();

    let status = unsafe {
        ecall_join_group(
            eid,
            &mut rt,
            &mut raw_reg_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx { status, function: "ecall_join_group" }.into());
    }
    if rt.is_err() {
        return Err(HostError::Enclave { status: rt, function: "ecall_join_group" }.into());
    }

    Ok(raw_reg_tx)
}

/// Handshake to other group members to update the group key
pub(crate) fn handshake(
    eid: sgx_enclave_id_t,
) -> Result<RawHandshakeTx> {
    let mut rt = EnclaveStatus::default();
    let mut raw_handshake_tx = RawHandshakeTx::default();

    let status = unsafe {
        ecall_handshake(
            eid,
            &mut rt,
            &mut raw_handshake_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx { status, function: "ecall_handshake" }.into());
    }
    if rt.is_err() {
        return Err(HostError::Enclave { status: rt, function: "ecall_handshake" }.into());
    }

    Ok(raw_handshake_tx)
}

pub(crate) fn register_notification(
    eid: sgx_enclave_id_t,
    access_right: AccessRight,
) -> Result<()> {
    let mut rt = EnclaveStatus::default();

    let status = unsafe {
        ecall_register_notification(
            eid,
            &mut rt,
            access_right.sig().to_bytes().as_ptr() as _,
            access_right.pubkey().to_bytes().as_ptr() as _,
            access_right.challenge().as_ptr() as _,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx { status, function: "ecall_register_notification" }.into());
    }
    if rt.is_err() {
        return Err(HostError::Enclave { status: rt, function: "ecall_register_notification" }.into());
    }

    Ok(())
}
