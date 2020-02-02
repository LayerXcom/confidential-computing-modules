#![allow(dead_code)]

use std::{path::Path, sync::Arc};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use anonify_common::{AccessRight, State, UserAddress};
use super::{
    eth::primitives::Web3Contract,
    eventdb::BlockNumDB,
};
use crate::error::{Result, HostErrorKind};
use self::traits::*;

/// This dispatcher communicates with a blockchain node.
#[derive(Debug, Clone)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    inner: Arc<RwLock<InnerDispatcher<D,S,W,DB>>>,
}

impl<D, S, W, DB> Dispatcher<D, S, W, DB>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    pub fn new(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let inner = InnerDispatcher::new_with_deployer(enclave_id, node_url, event_db)?;

        Ok(Dispatcher {
            inner: Arc::new(RwLock::new(inner))
        })
    }

    pub fn set_contract_addr<P>(&self, contract_addr: &str, abi_path: P) -> Result<()>
    where
        P: AsRef<Path> + Copy,
    {
        let mut inner = self.inner.write();
        inner.set_contract_addr(contract_addr, abi_path);

        Ok(())
    }

    pub fn deploy<ST: State>(
        &self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
        state: ST,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        inner.deploy(deploy_user, access_right, state)
    }

    pub fn send_tx<ST, P>(
        &self,
        access_right: &AccessRight,
        target: &UserAddress,
        state: ST,
        from_eth_addr: SignerAddress,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String>
    where
        ST: State,
        P: AsRef<Path> + Copy,
    {
        let mut inner = self.inner.write();
        inner.send_tx(access_right, target, state, from_eth_addr, gas, contract_addr, abi_path)
    }

    pub fn block_on_event<P: AsRef<Path> + Copy>(
        &self,
        contract_addr: &str,
        abi_path: P
    ) -> Result<()> {
        let mut inner = self.inner.write();
        inner.block_on_event(contract_addr, abi_path)
    }

    pub fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.inner.read().get_account(index)
    }
}

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
struct InnerDispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    deployer: D,
    sender: Option<S>,
    watcher: Option<W>,
    event_db: Arc<DB>,
}

impl<D, S, W, DB> InnerDispatcher<D, S, W, DB>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    fn new_with_deployer(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let deployer = D::new(enclave_id, node_url)?;

        Ok(InnerDispatcher {
            deployer,
            event_db,
            sender: None,
            watcher: None,
        })
    }

    fn set_contract_addr<P>(&mut self, contract_addr: &str, abi_path: P) -> Result<()>
    where
        P: AsRef<Path> + Copy
    {
        let enclave_id = self.deployer.get_enclave_id();
        let node_url = self.deployer.get_node_url();
        let sender = S::new(enclave_id, node_url, contract_addr, abi_path)?;
        let watcher = W::new(node_url, abi_path, contract_addr, self.event_db.clone())?;

        self.sender = Some(sender);
        self.watcher = Some(watcher);

        Ok(())
    }

    fn deploy<ST: State>(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
        state: ST,
    ) -> Result<String> {
        self.deployer.deploy(deploy_user, access_right, state)
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.deployer.get_account(index)
    }

    fn block_on_event<P: AsRef<Path> + Copy>(
        &mut self,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<()> {
        // If contract address is not set, set new contract address and abi path to generate watcher instance.
        // if let None = self.watcher.as_mut() {
            self.set_contract_addr(contract_addr, abi_path)?;
        // }

        let eid = self.deployer.get_enclave_id();
        self.watcher.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set."))?
            .block_on_event(eid)
    }

    fn send_tx<ST, P>(
        &mut self,
        access_right: &AccessRight,
        target: &UserAddress,
        state: ST,
        from_eth_addr: SignerAddress,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String>
    where
        ST: State,
        P: AsRef<Path> + Copy,
    {
        // If contract address is not set, set new contract address and abi path to generate sender instance.
        // if let None = self.sender.as_mut() {
            self.set_contract_addr(contract_addr, abi_path)?;
        // }

        self.sender.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set collectly."))?
            .send_tx(access_right, target, state, from_eth_addr, gas)
    }
}

/// A type of transaction signing address
#[derive(Debug)]
pub enum SignerAddress {
    EthAddress(web3::types::Address)
}

/// A type of contract
pub enum ContractKind {
    Web3Contract(Web3Contract)
}

pub mod traits {
    use super::*;

    /// A trait for deploying contracts
    pub trait Deployer: Sized {
        fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self>;

        fn get_account(&self, index: usize) -> Result<SignerAddress>;

        fn deploy<ST: State>(
            &mut self,
            deploy_user: &SignerAddress,
            access_right: &AccessRight,
            state: ST,
        ) -> Result<String>;

        fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind>;

        fn get_enclave_id(&self) -> sgx_enclave_id_t;

        fn get_node_url(&self) -> &str;
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

        fn send_tx<ST: State>(
            &self,
            access_right: &AccessRight,
            target: &UserAddress,
            state: ST,
            from_eth_addr: SignerAddress,
            gas: u64,
        ) -> Result<String>;

        fn get_contract(self) -> ContractKind;
    }

    /// A trait of fetching event from blockchian nodes
    pub trait Watcher: Sized {
        type WatcherDB: BlockNumDB;

        fn new<P: AsRef<Path>>(
            node_url: &str,
            abi_path: P,
            contract_addr: &str,
            event_db: Arc<Self::WatcherDB>,
        ) -> Result<Self>;

        /// Blocking event fetch from blockchain nodes.
        fn block_on_event(
            &self,
            eid: sgx_enclave_id_t,
        ) -> Result<()>;

        fn get_contract(self) -> ContractKind;
    }
}
