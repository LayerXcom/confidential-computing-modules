use std::boxed::Box;
use sgx_types::*;
use anonify_types::{traits::SliceCPtr, EnclaveState, RawRegisterTx, RawInstructionTx, RawHandshakeTx};
use anonify_common::{AccessRight, IntoVec};
use anonify_app_preluder::{mem_name_to_id, CIPHERTEXT_SIZE};
use anonify_runtime::traits::State;
use anonify_bc_connector::{
    eventdb::InnerEnclaveLog,
    utils::StateInfo,
    error::{HostError, Result},
};
use ed25519_dalek::{Signature, PublicKey};
use log::debug;
use crate::auto_ffi::*;

pub(crate) fn insert_logs(
    eid: sgx_enclave_id_t,
    enclave_log: &InnerEnclaveLog,
) -> Result<()> {
    if enclave_log.ciphertexts.len() != 0 && enclave_log.handshakes.len() == 0 {
        insert_ciphertexts(eid, &enclave_log)?;
    } else if enclave_log.ciphertexts.len() == 0 && enclave_log.handshakes.len() != 0 {
        // The size of handshake cannot be calculated in this host directory,
        // so the ecall_insert_handshake function is repeatedly called over the number of fetched handshakes.
        for handshake in &enclave_log.handshakes {
            insert_handshake(eid, handshake)?;
        }
    } else {
        debug!("No logs to insert into the enclave.");
    }

    Ok(())
}
/// Insert event logs from blockchain nodes into enclave memory database.
fn insert_ciphertexts(
    eid: sgx_enclave_id_t,
    enclave_log: &InnerEnclaveLog,
) -> Result<()> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let len = enclave_log.ciphertexts.len() * CIPHERTEXT_SIZE;
    let buf = enclave_log.ciphertexts.clone().into_iter().flat_map(|e| e.into_vec()).collect::<Vec<u8>>();

    let status = unsafe {
        ecall_insert_ciphertexts(
            eid,
            &mut rt,
            enclave_log.contract_addr.as_ptr() as _,
            enclave_log.latest_blc_num,
            buf.as_c_ptr() as *mut u8,
            len,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status, function: "ecall_insert_ciphertexts" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status: rt, function: "ecall_insert_ciphertexts" }.into());
    }

    Ok(())
}

fn insert_handshake(
    eid: sgx_enclave_id_t,
    handshake: &[u8],
) -> Result<()> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let status = unsafe {
        ecall_insert_handshake(
            eid,
            &mut rt,
            handshake.as_c_ptr() as *mut u8,
            handshake.len(),
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status, function: "ecall_insert_handshake" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status: rt, function: "ecall_insert_handshake" }.into());
    }

    Ok(())
}

/// Get state only if the signature verification returns true.
pub(crate) fn get_state_from_enclave(
    eid: sgx_enclave_id_t,
    sig: &Signature,
    pubkey: &PublicKey,
    msg: &[u8],
    mem_name: &str,
) -> Result<Vec<u8>>
{
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut state = EnclaveState::default();
    let mem_id = mem_name_to_id(mem_name).as_raw();

    let status = unsafe {
        ecall_get_state(
            eid,
            &mut rt,
            sig.to_bytes().as_ptr() as _,
            pubkey.to_bytes().as_ptr() as _,
            msg.as_ptr() as _,
            mem_id,
            &mut state,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status, function: "ecall_get_state" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status: rt, function: "ecall_get_state" }.into());
    }

    Ok(state_as_bytes(state).into())
}

fn state_as_bytes(state: EnclaveState) -> Box<[u8]> {
    let raw_state = state.0 as *mut Box<[u8]>;
    let box_state = unsafe { Box::from_raw(raw_state) };

    *box_state
}

pub(crate) fn register(eid: sgx_enclave_id_t) -> Result<RawRegisterTx> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut raw_reg_tx = RawRegisterTx::default();

    let status = unsafe {
        ecall_register(
            eid,
            &mut rt,
            &mut raw_reg_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status, function: "ecall_register" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status: rt, function: "ecall_register" }.into());
    }

    Ok(raw_reg_tx)
}

pub(crate) fn encrypt_instruction<S: State>(
    eid: sgx_enclave_id_t,
    access_right: AccessRight,
    state_info: StateInfo<'_, S>,
) -> Result<RawInstructionTx> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut raw_instruction_tx = RawInstructionTx::default();
    let state = state_info.state_as_bytes();
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
        return Err(HostError::Sgx{ status, function: "ecall_encrypt_instruction" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status: rt, function: "ecall_encrypt_instruction" }.into());
    }

    Ok(raw_instruction_tx)
}

/// Handshake to other group members to update the group key
pub(crate) fn handshake(
    eid: sgx_enclave_id_t,
) -> Result<RawHandshakeTx> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut raw_handshake_tx = RawHandshakeTx::default();

    let status = unsafe {
        ecall_handshake(
            eid,
            &mut rt,
            &mut raw_handshake_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status, function: "ecall_handshake" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status: rt, function: "ecall_handshake" }.into());
    }

    Ok(raw_handshake_tx)
}
