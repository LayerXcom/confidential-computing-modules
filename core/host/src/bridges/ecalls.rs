use sgx_types::*;
use anonify_types::{RawUnsignedTx, traits::SliceCPtr, EnclaveState, RawRegisterTx};
use anonify_common::State;
use ed25519_dalek::{Signature, PublicKey};
use crate::auto_ffi::*;
use crate::transaction::eventdb::InnerEnclaveLog;
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
            enclave_log.ciphertexts.len(),
            enclave_log.ciphertext_size,
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

    let res = S::from_bytes(&state_as_bytes(state))?;
    Ok(res)
}

fn state_as_bytes(state: EnclaveState) -> Box<[u8]> {
    let raw_state = state.0 as *mut Box<[u8]>;
    let box_state = unsafe { Box::from_raw(raw_state) };

    *box_state
}

/// Initialize a state when a new contract is deployed.
pub(crate) fn init_state<S: State>(
    eid: sgx_enclave_id_t,
    sig: &Signature,
    pubkey: &PublicKey,
    msg: &[u8],
    state: S,
) -> Result<UnsignedTx> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut unsigned_tx = RawUnsignedTx::default();
    let state = state.as_bytes()?;

    let status = unsafe {
        ecall_init_state(
            eid,
            &mut rt,
            sig.to_bytes().as_ptr() as _,
            pubkey.to_bytes().as_ptr() as _,
            msg.as_ptr() as _,
            state.as_c_ptr() as *const u8,
            state.len(),
            &mut unsigned_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status, function: "ecall_init_state" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_init_state" }.into());
    }

    Ok(unsigned_tx.into())
}

/// Update states when a transaction is sent to blockchain.
pub(crate) fn state_transition<S: State>(
    eid: sgx_enclave_id_t,
    sig: &Signature,
    pubkey: &PublicKey,
    msg: &[u8],
    target: &[u8],
    state: S,
) -> Result<UnsignedTx> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut unsigned_tx = RawUnsignedTx::default();
    let state = state.as_bytes()?;

    let status = unsafe {
        ecall_state_transition(
            eid,
            &mut rt,
            sig.to_bytes().as_ptr() as _,
            pubkey.to_bytes().as_ptr() as _,
            msg.as_ptr() as _,
            target.as_ptr() as _,
            state.as_c_ptr() as *const u8,
            state.len(),
            &mut unsigned_tx,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status, function: "ecall_contract_deploy" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_contract_deploy" }.into());
    }

    Ok(unsigned_tx.into())
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
pub(crate) struct UnsignedTx {
    pub report: Box<[u8]>,
    pub report_sig: Box<[u8]>,
    /// The number of ciphertexts.
    pub ciphertext_num: usize,
    pub ciphertexts: Box<[u8]>,
}

impl From<RawUnsignedTx> for UnsignedTx {
    fn from(raw_tx: RawUnsignedTx) -> Self {
        let mut res_tx: UnsignedTx = Default::default();

        let box_report = raw_tx.report as *mut Box<[u8]>;
        let report = unsafe { Box::from_raw(box_report) };
        let box_report_sig = raw_tx.report_sig as *mut Box<[u8]>;
        let report_sig = unsafe { Box::from_raw(box_report_sig) };
        let box_ciphertexts = raw_tx.ciphertexts as *mut Box<[u8]>;
        let ciphertexts = unsafe { Box::from_raw(box_ciphertexts) };

        res_tx.report = *report;
        res_tx.report_sig = *report_sig;
        res_tx.ciphertexts = *ciphertexts;
        res_tx.ciphertext_num = raw_tx.ciphertext_num;

        res_tx
    }
}


impl UnsignedTx {
    pub(crate) fn get_two_ciphertexts(&self) -> (&[u8], &[u8]) {
        let c_size = self.ciphertexts.len() / self.ciphertext_num;
        let (c1, c2) = self.ciphertexts.split_at(c_size);
        assert_eq!(c1.len(), c2.len());

        (c1, c2)
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
    fn test_init_state() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let total_supply = 100;

        assert!(init_state(
            enclave.geteid(),
            &sig,
            &keypair.public,
            &msg,
            MockState::new(total_supply),
        ).is_ok());
    }

    #[test]
    fn test_state_transition() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let amount = 0;
        let target: [u8; 20] = csprng.gen();

        assert!(state_transition(
            enclave.geteid(),
            &sig,
            &keypair.public,
            &msg,
            &target[..],
            MockState::new(amount),
        ).is_ok());
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
