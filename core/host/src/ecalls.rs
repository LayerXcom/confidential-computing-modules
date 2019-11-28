use sgx_types::*;
use anonify_types::{Sig, PubKey, Msg};
use crate::auto_ffi::ecall_get_state;
use crate::init_enclave::EnclaveDir;

/// Get state only if the signature verification returns true.
pub fn get_state(
    eid: sgx_enclave_id_t,
    sig: &Sig,
    pubkey: &PubKey,
    msg: &Msg
) -> u64 {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut res: u64 = Default::default();

    let state = unsafe {
        ecall_get_state(
            eid,
            &mut retval,
            sig.as_ptr() as _,
            pubkey.as_ptr() as _,
            msg.as_ptr() as _,
            res as _,
        )
    };

    res
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
