use std::boxed::Box;
use sgx_types::*;
use anonify_types::{traits::SliceCPtr, EnclaveState, RawRegisterTx, RawStateTransTx};
use anonify_common::AccessRight;
use anonify_app_preluder::{mem_name_to_id, CIPHERTEXT_SIZE};
use anonify_runtime::State;
use anonify_rpc_handler::{
    eventdb::InnerEnclaveLog,
    utils::StateInfo,
};
use ed25519_dalek::{Signature, PublicKey};
use crate::auto_ffi::*;
use anonify_rpc_handler::error::{HostError, Result};

/// Insert event logs from blockchain nodes into enclave memory database.
pub(crate) fn insert_logs(
    eid: sgx_enclave_id_t,
    enclave_log: &InnerEnclaveLog,
) -> Result<()> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let len = enclave_log.ciphertexts.len() * (*CIPHERTEXT_SIZE);
    let buf = enclave_log.ciphertexts.clone().into_iter().flat_map(|e| e.0).collect::<Vec<u8>>();

    let status = unsafe {
        ecall_insert_logs(
            eid,
            &mut rt,
            enclave_log.contract_addr.as_ptr() as _,
            enclave_log.latest_blc_num,
            buf.as_c_ptr() as *const u8,
            len,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status, function: "ecall_insert_logs" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostError::Sgx{ status: rt, function: "ecall_insert_logs" }.into());
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

/// Update states when a transaction is sent to blockchain.
pub(crate) fn state_transition<S: State>(
    eid: sgx_enclave_id_t,
    access_right: AccessRight,
    state_info: StateInfo<'_, S>,
) -> Result<RawStateTransTx> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut raw_state_tx = RawStateTransTx::default();
    let state = state_info.state_as_bytes();
    let call_id = state_info.call_name_to_id();

    let status = unsafe {
        ecall_state_transition(
            eid,
            &mut rt,
            access_right.sig().to_bytes().as_ptr() as _,
            access_right.pubkey().to_bytes().as_ptr() as _,
            access_right.challenge().as_ptr() as _,
            state.as_c_ptr() as *mut u8,
            state.len(),
            state_info.state_id(),
            call_id,
            &mut raw_state_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status, function: "ecall_contract_deploy" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(HostError::Sgx{ status: rt, function: "ecall_contract_deploy" }.into());
    }

    Ok(raw_state_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_os::OsRng;
    use rand::Rng;
    use ed25519_dalek::Keypair;
    use crate::init_enclave::EnclaveDir;

    #[test]
    #[ignore]
    fn test_init_state() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let total_supply = 100;
        let state_id = 0;

        // assert!(init_state(
        //     enclave.geteid(),
        //     &sig,
        //     &keypair.public,
        //     &msg,
        //     MockState::new(total_supply),
        //     state_id,
        // ).is_ok());
    }

    #[test]
    #[ignore]
    fn test_state_transition() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let amount = 0;
        let target: [u8; 20] = csprng.gen();

        // assert!(state_transition(
        //     enclave.geteid(),
        //     &sig,
        //     &keypair.public,
        //     &msg,
        //     &target[..],
        //     MockState::new(amount),
        // ).is_ok());
    }

    #[test]
    #[ignore]
    fn test_ecall_get_state() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        // let state = get_state_from_enclave::<Value>(enclave.geteid(), &sig, &keypair.public, &msg);
        // assert_eq!(state, 0);
    }
}
