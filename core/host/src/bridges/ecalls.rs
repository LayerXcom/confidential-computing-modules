use sgx_types::*;
use anonify_types::{traits::SliceCPtr, EnclaveState, RawRegisterTx, RawStateTransTx};
use anonify_common::{State, AccessRight, UserAddress, LockParam, Ciphertext, CIPHERTEXT_SIZE};
use ed25519_dalek::{Signature, PublicKey};
use crate::auto_ffi::*;
use crate::transaction::{
    eventdb::InnerEnclaveLog,
    utils::StateInfo,
};
use crate::error::{HostErrorKind, Result};

/// Insert event logs from blockchain nodes into enclave memory database.
pub(crate) fn insert_logs(
    eid: sgx_enclave_id_t,
    enclave_log: &InnerEnclaveLog,
) -> Result<()> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let status = unsafe {
        ecall_insert_logs(
            eid,
            &mut rt,
            enclave_log.contract_addr.as_ptr() as _,
            enclave_log.latest_blc_num,
            enclave_log.ciphertexts.as_c_ptr() as *const u8,
            enclave_log.ciphertexts.len() * CIPHERTEXT_SIZE,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status, function: "ecall_insert_logs" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_insert_logs" }.into());
    }

    Ok(())
}

/// Get state only if the signature verification returns true.
pub(crate) fn get_state<S: State>(
    eid: sgx_enclave_id_t,
    sig: &Signature,
    pubkey: &PublicKey,
    msg: &[u8],
) -> Result<S> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut state = EnclaveState::default();

    let status = unsafe {
        ecall_get_state(
            eid,
            &mut rt,
            sig.to_bytes().as_ptr() as _,
            pubkey.to_bytes().as_ptr() as _,
            msg.as_ptr() as _,
            &mut state,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status, function: "ecall_get_state" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_get_state" }.into());
    }

    let mut s = state_as_bytes(state);
    let res = S::from_bytes(&mut s)?;
    Ok(res)
}

fn state_as_bytes(state: EnclaveState) -> Box<[u8]> {
    let raw_state = state.0 as *mut Box<[u8]>;
    let box_state = unsafe { Box::from_raw(raw_state) };

    *box_state
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BoxedRegisterTx {
    pub report: Box<[u8]>,
    pub report_sig: Box<[u8]>,
}

impl BoxedRegisterTx {
    pub(crate) fn register(eid: sgx_enclave_id_t) -> Result<Self> {
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
            return Err(HostErrorKind::Sgx{ status, function: "ecall_register" }.into());
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_register" }.into());
        }

        Ok(raw_reg_tx.into())
    }
}

impl From<RawRegisterTx> for BoxedRegisterTx {
    fn from(raw_reg_tx: RawRegisterTx) -> Self {
        let mut res_tx = BoxedRegisterTx::default();

        let box_report = raw_reg_tx.report as *mut Box<[u8]>;
        let report = unsafe { Box::from_raw(box_report) };
        let box_report_sig = raw_reg_tx.report_sig as *mut Box<[u8]>;
        let report_sig = unsafe { Box::from_raw(box_report_sig) };

        res_tx.report = *report;
        res_tx.report_sig = *report_sig;

        res_tx
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BoxedStateTransTx {
    pub state_id: u64,
    pub ciphertext: Box<[u8]>,
    pub lock_param: Box<[u8]>,
    pub enclave_sig: Box<[u8]>,
}

impl BoxedStateTransTx {
    /// Initialize a state when a new contract is deployed.
    pub(crate) fn init_state<S: State>(
        eid: sgx_enclave_id_t,
        access_right: AccessRight,
        state: S,
        state_id: u64,
    ) -> Result<Self> {
        let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let mut raw_state_tx = RawStateTransTx::default();
        let state = state.as_bytes();

        let status = unsafe {
            ecall_init_state(
                eid,
                &mut rt,
                access_right.sig().to_bytes().as_ptr() as _,
                access_right.pubkey().to_bytes().as_ptr() as _,
                access_right.challenge().as_ptr() as _,
                state.as_c_ptr() as *mut u8,
                state.len(),
                state_id,
                &mut raw_state_tx,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(HostErrorKind::Sgx{ status, function: "ecall_init_state" }.into());
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_init_state" }.into());
        }

        Ok(raw_state_tx.into())
    }

    /// Update states when a transaction is sent to blockchain.
    pub(crate) fn state_transition<S: State>(
        eid: sgx_enclave_id_t,
        access_right: AccessRight,
        target: &UserAddress,
        state_info: StateInfo<'_, S>,
    ) -> Result<Self> {
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
                target.as_bytes().as_ptr() as _,
                state.as_c_ptr() as *mut u8,
                state.len(),
                state_info.state_id(),
                call_id,
                &mut raw_state_tx,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(HostErrorKind::Sgx{ status, function: "ecall_contract_deploy" }.into());
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_contract_deploy" }.into());
        }

        Ok(raw_state_tx.into())
    }

    pub fn get_ciphertexts(&self) -> impl Iterator<Item=Ciphertext> + '_ {
        Ciphertext::from_bytes_iter(&self.ciphertext)
    }

    pub fn get_lock_params(&self) -> impl Iterator<Item=LockParam> + '_ {
        LockParam::from_bytes_iter(&self.lock_param)
    }
}

impl From<RawStateTransTx> for BoxedStateTransTx {
    fn from(raw_state_tx: RawStateTransTx) -> Self {
        let mut res_tx = BoxedStateTransTx::default();

        let box_ciphertext = raw_state_tx.ciphertext as *mut Box<[u8]>;
        let ciphertext = unsafe { Box::from_raw(box_ciphertext) };
        let box_lock_param = raw_state_tx.lock_param as *mut Box<[u8]>;
        let lock_param = unsafe { Box::from_raw(box_lock_param) };
        let box_enclave_sig = raw_state_tx.enclave_sig as *mut Box<[u8]>;
        let enclave_sig = unsafe { Box::from_raw(box_enclave_sig) };

        res_tx.state_id = raw_state_tx.state_id;
        res_tx.ciphertext = *ciphertext;
        res_tx.lock_param = *lock_param;
        res_tx.enclave_sig = *enclave_sig;

        res_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_os::OsRng;
    use rand::Rng;
    use ed25519_dalek::Keypair;
    use crate::init_enclave::EnclaveDir;
    use crate::mock::MockState;

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

        // let state = get_state::<Value>(enclave.geteid(), &sig, &keypair.public, &msg);
        // assert_eq!(state, 0);
    }
}
