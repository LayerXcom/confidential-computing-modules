use std::{
    path::Path,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use anonify_common::plugin_types::*;
use frame_common::{
    traits::*,
    crypto::AccessRight,
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

    fn get_account(&self, index: usize) -> Result<Address> {
        self.web3_conn.get_account(index)
    }

    fn deploy<F>(
        &mut self,
        deploy_user: &Address,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<output::ReturnJoinGroup>,
    {
        let output = reg_fn(self.enclave_id)?;

        let contract_addr = self.web3_conn.deploy(
            &deploy_user,
            output.report(),
            output.report_sig(),
            output.handshake(),
        )?;
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

    fn register_notification<F>(
        &self,
        access_right: AccessRight,
        reg_notify_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(sgx_enclave_id_t, AccessRight) -> Result<()>,
    {
        reg_notify_fn(self.enclave_id, access_right)
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

    fn get_account(&self, index: usize) -> Result<Address> {
        self.contract.get_account(index)
    }

    fn join_group<F>(
        &self,
        signer: Address,
        gas: u64,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<output::ReturnJoinGroup>,
    {
        let output = reg_fn(self.enclave_id)?;
        let receipt = self.contract.join_group(
            signer,
            output.report(),
            output.report_sig(),
            output.handshake(),
            gas
        )?;

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn send_instruction(
        &self,
        host_output: host_output::Instruction,
    ) -> Result<String> {
        let receipt = self.contract.send_instruction(host_output)?;

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn handshake<F>(
        &self,
        signer: Address,
        gas: u64,
        handshake_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<output::ReturnHandshake>
    {
        let output = handshake_fn(self.enclave_id)?;
        let receipt = self.contract.handshake(
            signer,
            output.handshake(),
            gas
        )?;

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

    fn block_on_event<F, S>(
        &self,
        eid: sgx_enclave_id_t,
        insert_fn: F,
    ) -> Result<Option<Vec<UpdatedState<S>>>>
    where
        F: FnOnce(sgx_enclave_id_t, InnerEnclaveLog) -> Result<Option<Vec<UpdatedState<S>>>>,
        S: State,
    {
        let enclave_updated_state = self.contract
            .get_event(self.event_db.clone(), self.contract.address())?
            .into_enclave_log()?
            .insert_enclave(eid, insert_fn)?
            .set_to_db(self.contract.address());

        Ok(enclave_updated_state.updated_states())
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}
