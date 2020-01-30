use std::{path::Path, sync::Arc};
use sgx_types::sgx_enclave_id_t;
use anonify_common::{AccessRight, State, UserAddress};
use web3::types::{H160, H256};
use super::{
    eth::primitives::Web3Contract,
    eventdb::{EventDB, BlockNumDB},
};
use crate::error::Result;

/// Dispatcher communicates with a blockchain node.
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher> {
    deployer: D,
    sender: S,
    watcher: W,
}

// impl Dispatcher {
//     pub fn new<D: BlockNumDB>(
//         enclave_id: sgx_enclave_id_t,
//         node_url: &str,
//         event_db: Arc<D>,
//     ) -> Self {

//     }
// }

/// A trait for deploying contracts
pub trait Deployer: Sized {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self>;

    fn get_account(&self, index: usize) -> Result<SignerAddress>;

    fn deploy<S: State>(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
        state: S,
    ) -> Result<H160>;

    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind>;
}

/// A trait for sending transactions to blockchain nodes
pub trait Sender: Sized {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<Self>;

    fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: ContractKind,
    ) -> Self;

    fn get_account(&self, index: usize) -> Result<SignerAddress>;

    fn send_tx<S: State>(
        &self,
        access_right: &AccessRight,
        target: &UserAddress,
        state: S,
        from_eth_addr: SignerAddress,
        gas: u64,
    ) -> Result<H256>;

    fn get_contract(self) -> ContractKind;
}

/// A trait of fetching event from blockchian nodes
pub trait Watcher: Sized {
    type DB: BlockNumDB;

    fn new<P: AsRef<Path>>(
        node_url: &str,
        abi_path: P,
        contract_addr: &str,
        event_db: Arc<Self::DB>,
    ) -> Result<Self>;

    /// Blocking event fetch from blockchain nodes.
    fn block_on_event(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<()>;

    fn get_contract(self) -> ContractKind;
}

/// A type of transaction signing address
pub enum SignerAddress {
    EthAddress(web3::types::Address)
}

/// A type of contract
pub enum ContractKind {
    Web3Contract(Web3Contract)
}
