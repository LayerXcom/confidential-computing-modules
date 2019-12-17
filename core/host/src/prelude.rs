use sgx_types::sgx_enclave_id_t;
use log::debug;
use anonify_common::UserAddress;
use crate::{
    init_enclave::EnclaveDir,
    ecalls::*,
    error::Result,
    web3,
};

pub fn init_enclave() -> sgx_enclave_id_t {
    #[cfg(not(debug_assertions))]
    let enclave = EnclaveDir::new().init_enclave(false).unwrap();
    #[cfg(debug_assertions)]
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();

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

    debug!("unsigned_tx: {:?}", &unsigned_tx);

    let address = web3::deploy(
        eth_url,
        &unsigned_tx.ciphertexts,
        &unsigned_tx.report,
        &unsigned_tx.report_sig
    )?;

    Ok(address.to_fixed_bytes())
}

pub fn anonify_send(
    enclave_id: sgx_enclave_id_t,
    from_addr: &UserAddress,
    sig: &[u8],
    pubkey: &[u8],
    nonce: &[u8],
    target: &UserAddress,
    amount: u64,
    contract: &web3::AnonymousAssetContract,
    gas: u64,
) -> Result<()> {
    let unsigned_tx = state_transition(
        enclave_id,
        sig,
        pubkey,
        nonce,
        target.as_bytes(),
        amount,
    )?;

    debug!("unsigned_tx: {:?}", &unsigned_tx);

    let (update_bal1, update_bal2) = unsigned_tx.get_two_ciphertexts();
    let receipt = contract.tranfer::<u64>(
        from_addr.into(),
        update_bal1,
        update_bal2,
        &unsigned_tx.report,
        &unsigned_tx.report_sig,
        gas,
    )?;

    Ok(())
}
