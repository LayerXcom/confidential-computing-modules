use sgx_types::sgx_enclave_id_t;
use log::debug;
use anonify_common::UserAddress;
use ed25519_dalek::{Signature, PublicKey, Keypair};
use ::web3::types::{H160, H256, Address as EthAddress};
use rand::Rng;
use rand_core::{RngCore, CryptoRng};
use crate::{
    init_enclave::EnclaveDir,
    ecalls::*,
    error::Result,
    web3::{self, Web3Http},
};

pub fn init_enclave() -> sgx_enclave_id_t {
    #[cfg(not(debug_assertions))]
    let enclave = EnclaveDir::new().init_enclave(false).unwrap();
    #[cfg(debug_assertions)]
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();

    enclave.geteid()
}

/// Access right of Read/Write to anonify's enclave mem db.
pub struct AccessRight {
    sig: Signature,
    pubkey: PublicKey,
    nonce: [u8; 32],
}

impl AccessRight {
    pub fn new_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let keypair: Keypair = Keypair::generate(rng);
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&nonce);

        assert!(keypair.verify(&nonce, &sig).is_ok());

        Self::new(sig, keypair.public, nonce)
    }

    pub fn new(
        sig: Signature,
        pubkey: PublicKey,
        nonce: [u8; 32],
    ) -> Self {
        AccessRight {
            sig,
            pubkey,
            nonce,
        }
    }

    pub fn get_state(
        &self,
        enclave_id: sgx_enclave_id_t,
    ) -> Result<u64> {
        let state = get_state(
            enclave_id,
            &self.sig,
            &self.pubkey,
            &self.nonce,
        )?;

        debug!("state: {:?}", &state);
        Ok(state)
    }

    pub fn user_address(&self) -> UserAddress {
        UserAddress::from_pubkey(&self.pubkey())
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }
}

#[derive(Debug)]
pub struct EthDeployer {
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http
}

impl EthDeployer {
    pub fn new(enclave_id: sgx_enclave_id_t, web3_conn: Web3Http) -> Self {
        EthDeployer {
            enclave_id,
            web3_conn,
        }
    }

    pub fn deploy(
        &self,
        deploy_user: &EthAddress,
        access_right: &AccessRight,
        total_supply: u64,
    ) -> Result<H160> {
        let unsigned_tx = init_state(
            self.enclave_id,
            &access_right.sig,
            &access_right.pubkey,
            &access_right.nonce,
            total_supply,
        )?;

        debug!("unsigned_tx: {:?}", &unsigned_tx);

        let contract_addr = self.web3_conn.deploy(
            &deploy_user,
            &unsigned_tx.ciphertexts,
            &unsigned_tx.report,
            &unsigned_tx.report_sig,
        )?;

        Ok(contract_addr)
    }
}

pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: web3::AnonymousAssetContract,
}

impl EthSender {
    pub fn new(
        enclave_id: sgx_enclave_id_t,
        contract: web3::AnonymousAssetContract
    ) -> Self {
        EthSender {
            enclave_id,
            contract,
        }
    }

    pub fn send_tx(
        &self,
        access_right: &AccessRight,
        from_eth_addr: EthAddress,
        target: &UserAddress,
        amount: u64,
        gas: u64,
    ) -> Result<H256> {
        let unsigned_tx = state_transition(
            self.enclave_id,
            &access_right.sig,
            &access_right.pubkey,
            &access_right.nonce,
            target.as_bytes(),
            amount,
        )?;

        debug!("unsigned_tx: {:?}", &unsigned_tx);

        let (update_bal1, update_bal2) = unsigned_tx.get_two_ciphertexts();
        let receipt = self.contract.tranfer::<u64>(
            from_eth_addr,
            update_bal1,
            update_bal2,
            &unsigned_tx.report,
            &unsigned_tx.report_sig,
            gas,
        )?;

        Ok(receipt)
    }
}
