use sgx_types::*;
use anonify_types::{Sig, PubKey, Msg};
use crate::auto_ffi::*;
use crate::init_enclave::EnclaveDir;
use crate::error::{HostErrorKind, Result};

/// Get state only if the signature verification returns true.
pub fn get_state(
    eid: sgx_enclave_id_t,
    sig: &Sig,
    pubkey: &PubKey,
    msg: &Msg
) -> Result<u64> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut res: u64 = Default::default();

    let status = unsafe {
        ecall_get_state(
            eid,
            &mut rt,
            sig.as_ptr() as _,
            pubkey.as_ptr() as _,
            msg.as_ptr() as _,
            res as _,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status, function: "ecall_get_state" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_get_state" }.into());
    }

    Ok(res)
}

pub fn init_state(
    eid: sgx_enclave_id_t,
    sig: &Sig,
    pubkey: &PubKey,
    total_supply: u64,
) -> Result<[u8; 60]> {
    let mut rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut ciphertext = [0u8; 60];

    let status = unsafe {
        ecall_init_state(
            eid,
            &mut rt,
            sig.as_ptr() as _,
            pubkey.as_ptr() as _,
            total_supply as _,
            ciphertext.as_ptr() as _,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status, function: "ecall_contract_deploy" }.into());
    }
    if rt != sgx_status_t::SGX_SUCCESS {
		return Err(HostErrorKind::Sgx{ status: rt, function: "ecall_contract_deploy" }.into());
    }

    Ok(ciphertext)
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;
    use rand_os::OsRng;
    use rand::Rng;
    use ed25519_dalek::Keypair;

    #[test]
    #[ignore]
    fn test_ecall_get_state() {
        let enclave = EnclaveDir::new().init_enclave().unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let state = get_state(enclave.geteid(), &sig.to_bytes(), &keypair.public.to_bytes(), &msg);
        assert_eq!(state, 0);
    }
}
