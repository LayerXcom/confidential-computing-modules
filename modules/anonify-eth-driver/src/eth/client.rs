use std::{
    path::Path,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use anonify_io_types::*;
use frame_common::{
    traits::*,
    state_types::UpdatedState,
};
use web3::types::Address;
use crate::{
    error::Result,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    traits::*,
    utils::*,
    workflow::*,
};
use super::primitives::{Web3Http, Web3Contract};

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http,
    address: Option<Address>, // contract address
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

    fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.web3_conn.get_account(index, password)
    }

    fn deploy(
        &mut self,
        host_output: host_output::JoinGroup,
        confirmations: usize,
    ) -> Result<String> {
        let contract_addr = self.web3_conn.deploy(host_output, confirmations)?;
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

    fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.contract.get_account(index, password)
    }

    fn join_group(
        &self,
        host_output: host_output::JoinGroup,
        confirmations: usize,
    ) -> Result<String> {
        let receipt = self.contract.join_group(host_output, confirmations)?;

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn send_instruction(
        &self,
        host_output: host_output::Instruction,
        confirmations: usize,
    ) -> Result<String> {
        let receipt = self.contract.send_instruction(host_output, confirmations)?;

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn handshake(
        &self,
        host_output: host_output::Handshake,
        confirmations: usize,
    ) -> Result<String> {
        let receipt = self.contract.handshake(host_output, confirmations)?;

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

    fn block_on_event<S: State>(
        &self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        let enclave_updated_state = self.contract
            .get_event(self.event_db.clone(), self.contract.address())?
            .into_enclave_log()?
            .insert_enclave(eid)?
            .set_to_db(self.contract.address());

        Ok(enclave_updated_state.updated_states())
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}
