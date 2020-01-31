use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use log::debug;
use anonify_common::{UserAddress, AccessRight, State};
use ed25519_dalek::{Signature, PublicKey, Keypair};
use web3::types::{H160, H256, Address as EthAddress, BlockNumber};
use crate::{
    init_enclave::EnclaveDir,
    ecalls::*,
    error::Result,
    transaction::{
        eventdb::{EventDB, EventDBTx, BlockNumDB},
        dispatcher::*,
    },
};
use super::primitives::{self, Web3Http, EthEvent, Web3Contract, contract_abi_from_path};

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http,
    address: Option<EthAddress>, // contract address
}

impl Deployer for EthDeployer {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(node_url)?;

        Ok(EthDeployer {
            enclave_id,
            web3_conn,
            address: None,
        })
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        Ok(SignerAddress::EthAddress(
            self.web3_conn.get_account(index)?
        ))
    }

    fn deploy<ST: State>(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
        state: ST,
    ) -> Result<H160> {
        let unsigned_tx = init_state(
            self.enclave_id,
            &access_right.sig,
            &access_right.pubkey,
            &access_right.nonce,
            state,
        )?;
        debug!("unsigned_tx: {:?}", &unsigned_tx);

        let contract_addr = match deploy_user {
            SignerAddress::EthAddress(address) => {
                self.web3_conn.deploy(
                    &address,
                    &unsigned_tx.ciphertexts,
                    &unsigned_tx.report,
                    &unsigned_tx.report_sig,
                )?
            }
        };
        self.address = Some(contract_addr);

        Ok(contract_addr)
    }

    // TODO: generalize, remove abi.
    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind> {
        let abi = contract_abi_from_path(abi_path)?;
        let adderess = self.address.expect("The contract hasn't be deployed yet.");
        Ok(ContractKind::Web3Contract(
            Web3Contract::new(self.web3_conn, adderess, abi)?
        ))
    }

    fn get_enclave_id(&self) -> sgx_enclave_id_t {
        self.enclave_id
    }

    fn get_node_url(&self) -> &str {
        &self.web3_conn.get_eth_url()
    }
}

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: Web3Contract,
}

impl Sender for EthSender {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let abi = contract_abi_from_path(abi_path)?;
        let addr = EthAddress::from_str(contract_addr)?;
        let contract = Web3Contract::new(web3_http, addr, abi)?;

        Ok(EthSender { enclave_id, contract })
    }

    fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: ContractKind,
    ) -> Self {
        match contract {
            ContractKind::Web3Contract(contract) => {
                EthSender {
                    enclave_id,
                    contract,
                }
            }
        }
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        Ok(SignerAddress::EthAddress(
            self.contract.get_account(index)?
        ))
    }

    fn send_tx<S: State>(
        &self,
        access_right: &AccessRight,
        target: &UserAddress,
        state: S,
        from_eth_addr: SignerAddress,
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

        let receipt = match from_eth_addr {
            SignerAddress::EthAddress(addr) => {
                self.contract.tranfer::<u64>(
                    addr,
                    update_bal1,
                    update_bal2,
                    &unsigned_tx.report,
                    &unsigned_tx.report_sig,
                    gas,
                )?
            }
        };

        Ok(receipt)
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}

/// Components needed to watch events
pub struct EventWatcher<DB: BlockNumDB> {
    contract: Web3Contract,
    event_db: Arc<DB>,
}

impl<DB: BlockNumDB> Watcher for EventWatcher<DB> {
    type WatcherDB = DB;

    fn new<P: AsRef<Path>>(
        node_url: &str,
        abi_path: P,
        contract_addr: &str,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let abi = contract_abi_from_path(abi_path)?;
        let addr = EthAddress::from_str(contract_addr)?;
        let contract = Web3Contract::new(web3_http, addr, abi)?;

        Ok(EventWatcher { contract, event_db })
    }

    fn block_on_event(
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

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}
