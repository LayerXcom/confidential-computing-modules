use sgx_types::sgx_enclave_id_t;
use crate::{
    init_enclave::EnclaveDir,
    ecalls::{init_state, get_state},
    error::Result,
    web3,
};

pub fn init_enclave() -> sgx_enclave_id_t {
    let enclave = EnclaveDir::new().init_enclave().unwrap();
    enclave.geteid()
}

pub fn anonify_deploy(
    enclave_id: sgx_enclave_id_t,
    sig: &[u8],
    pubkey: &[u8],
    nonce: &[u8],
    total_supply: u64,
    eth_url: &str,
) -> Result<[u8; 20]> {
    let unsigned_tx = init_state(
        enclave_id,
        sig,
        pubkey,
        nonce,
        total_supply,
    )?;

    let address = web3::deploy(
        eth_url,
        &unsigned_tx.ciphertexts,
        &unsigned_tx.report,
        &unsigned_tx.report_sig
    )?;

    Ok(address.to_fixed_bytes())
}
