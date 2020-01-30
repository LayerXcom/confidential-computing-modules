use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use log::debug;
use anonify_common::{UserAddress, AccessRight, State};
use ed25519_dalek::{Signature, PublicKey, Keypair};
use ::web3::types::{H160, H256, Address as EthAddress, BlockNumber};
use crate::{
    init_enclave::EnclaveDir,
    ecalls::*,
    error::Result,
    web3::{self, Web3Http, EthEvent},
};
pub use crate::web3::eventdb::{EventDB, EventDBTx};

// TODO: This function throws error regarding invalid enclave id.
fn init_enclave() -> sgx_enclave_id_t {
    #[cfg(not(debug_assertions))]
    let enclave = EnclaveDir::new().init_enclave(false).unwrap();
    #[cfg(debug_assertions)]
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();

    enclave.geteid()
}

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http,
    address: Option<EthAddress>,
}

impl EthDeployer {
    pub fn new(enclave_id: sgx_enclave_id_t, eth_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(eth_url)?;

        Ok(EthDeployer {
            enclave_id,
            web3_conn,
            address: None,
        })
    }

    pub fn get_account(&self, index: usize) -> Result<EthAddress> {
        self.web3_conn.get_account(index)
    }

    pub fn deploy(
        &mut self,
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

        self.address = Some(contract_addr);

        Ok(contract_addr)
    }

    // TODO: generalize, remove abi.
    pub fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<web3::AnonymousAssetContract> {
        let abi = web3::contract_abi_from_path(abi_path)?;
        let adderess = self.address.expect("The contract hasn't be deployed yet.");
        web3::AnonymousAssetContract::new(self.web3_conn, adderess, abi)
    }
}

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: web3::AnonymousAssetContract,
}

impl EthSender {
    pub fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        eth_url: &str,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(eth_url)?;
        let abi = web3::contract_abi_from_path(abi_path)?;
        let addr = EthAddress::from_str(contract_addr)?;
        let contract = web3::AnonymousAssetContract::new(web3_http, addr, abi)?;

        Ok(EthSender { enclave_id, contract })
    }

    pub fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: web3::AnonymousAssetContract
    ) -> Self {
        EthSender {
            enclave_id,
            contract,
        }
    }

    pub fn get_account(&self, index: usize) -> Result<EthAddress> {
        self.contract.get_account(index)
    }

    pub fn send_tx<S: State>(
        &self,
        access_right: &AccessRight,
        target: &UserAddress,
        state: S,
        from_eth_addr: EthAddress,
        gas: u64,
    ) -> Result<H256> {
        let unsigned_tx = state_transition(
            self.enclave_id,
            &access_right.sig,
            &access_right.pubkey,
            &access_right.nonce,
            target.as_bytes(),
            state,
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

    pub fn get_contract(self) -> web3::AnonymousAssetContract {
        self.contract
    }
}

/// Components needed to watch events
pub struct EventWatcher {
    contract: web3::AnonymousAssetContract,
    event_db: Arc<EventDB>,
}

impl EventWatcher {
    pub fn new<P: AsRef<Path>>(
        eth_url: &str,
        abi_path: P,
        contract_addr: &str,
        event_db: Arc<EventDB>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(eth_url)?;
        let abi = web3::contract_abi_from_path(abi_path)?;
        let addr = EthAddress::from_str(contract_addr)?;
        let contract = web3::AnonymousAssetContract::new(web3_http, addr, abi)?;

        Ok(EventWatcher { contract, event_db })
    }

    /// Blocking event fetch from blockchain nodes.
    pub fn block_on_event(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<()> {
        let event = EthEvent::build_event();
        let key = event.signature();

        self.contract
            .get_event(self.event_db, key)?
            .into_enclave_log(&event)?
            .insert_enclave(eid)?
            .set_to_db(key);

        Ok(())
    }

    pub fn get_contract(self) -> web3::AnonymousAssetContract {
        self.contract
    }
}

pub trait StateGetter: Sized {
    type S: State;

    fn get_state_with_access_right(
        access_right: &AccessRight,
        enclave_id: sgx_enclave_id_t,
    ) -> Result<Self::S>;
}

pub struct StateHandler;


pub fn get_state_by_access_right<S: State>(
    access_right: &AccessRight,
    enclave_id: sgx_enclave_id_t,
) -> Result<S> {
    let state = get_state(
        enclave_id,
        &access_right.sig,
        &access_right.pubkey,
        &access_right.nonce,
    )?;

    Ok(state)
}
