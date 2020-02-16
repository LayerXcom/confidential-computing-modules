use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use log::debug;
use anonify_common::{UserAddress, AccessRight, State};
use web3::types::Address as EthAddress;
use crate::{
    ecalls::*,
    error::Result,
    transaction::{
        eventdb::BlockNumDB,
        dispatcher::{SignerAddress, ContractKind, traits::*},
        utils::ContractInfo,
    },
};
use super::primitives::{Web3Http, EthEvent, Web3Contract};

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

    fn deploy(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
    ) -> Result<String> {
        let register_tx = BoxedRegisterTx::register(self.enclave_id)?;

        let contract_addr = match deploy_user {
            SignerAddress::EthAddress(address) => {
                self.web3_conn.deploy(
                    &address,
                    &register_tx.report,
                    &register_tx.report_sig,
                )?
            }
        };
        self.address = Some(contract_addr);

        Ok(hex::encode(contract_addr.as_bytes()))
    }

    // TODO: generalize, remove abi.
    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind> {
        let addr = self.address.expect("The contract hasn't be deployed yet.").to_string();
        let contract_info = ContractInfo::new(abi_path, &addr);
        Ok(ContractKind::Web3Contract(
            Web3Contract::new(self.web3_conn, contract_info)?
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
        contract_info: ContractInfo<'_, P>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

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

    fn register(
        &self,
        from_eth_addr: SignerAddress,
        gas: u64,
    ) -> Result<String> {
        let register_tx = BoxedRegisterTx::register(self.enclave_id)?;
        let receipt = match from_eth_addr {
            SignerAddress::EthAddress(addr) => {
                self.contract.register(
                    addr,
                    &register_tx.report,
                    &register_tx.report_sig,
                    gas
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn init_state<ST: State>(
        &self,
        access_right: AccessRight,
        init_state: ST,
        state_id: u64,
        from_eth_addr: SignerAddress,
        gas: u64,
    )  -> Result<String> {
        let init_state_tx = BoxedStateTransTx::init_state(
            self.enclave_id, access_right, init_state, state_id
        )?;

        let receipt = match from_eth_addr {
            SignerAddress::EthAddress(addr) => {
                self.contract.init_state::<u64>(
                    addr,
                    init_state_tx.state_id,
                    &init_state_tx.ciphertext,
                    &init_state_tx.lock_param,
                    &init_state_tx.enclave_sig,
                    gas,
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn state_transition<ST: State>(
        &self,
        access_right: AccessRight,
        target: &UserAddress,
        state: ST,
        state_id: u64,
        call_name: &str,
        from_eth_addr: SignerAddress,
        gas: u64,
    ) -> Result<String> {
        // ecall of state transition
        let state_trans_tx = BoxedStateTransTx::state_transition(
            self.enclave_id, access_right, target, state, state_id, call_name
        )?;

        let ciphers = state_trans_tx.get_ciphertexts();
        let locks = state_trans_tx.get_lock_params();

        let receipt = match from_eth_addr {
            SignerAddress::EthAddress(addr) => {
                self.contract.state_transition(
                    addr,
                    state_trans_tx.state_id,
                    ciphers,
                    locks,
                    &state_trans_tx.enclave_sig,
                    gas,
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
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
        contract_info: ContractInfo<'_, P>,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EventWatcher { contract, event_db })
    }

    fn block_on_event(
        &self,
        eid: sgx_enclave_id_t,
    ) -> Result<()> {
        let event = EthEvent::build_event();
        let key = event.signature();

        self.contract
            .get_event(self.event_db.clone(), key)?
            .into_enclave_log()?
            .insert_enclave(eid)?
            .set_to_db(key);

        Ok(())
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}
