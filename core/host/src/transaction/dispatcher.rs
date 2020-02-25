#![allow(dead_code)]

use std::{path::Path, sync::Arc};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use crate::bridges::ecalls::{
    register as reg_fn,
    state_transition as st_fn,
    insert_logs as insert_fn,
};
use anonify_types::{RawRegisterTx, RawStateTransTx};
use anonify_common::{AccessRight, UserAddress};
use anonify_runtime::State;
use super::{
    eth::primitives::Web3Contract,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    utils::{ContractInfo, StateInfo},
};
use crate::error::{Result, HostErrorKind};
use self::traits::*;

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    inner: RwLock<InnerDispatcher<D,S,W,DB>>,
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
            inner: RwLock::new(inner)
        })
    }

    pub fn set_contract_addr<P>(&mut self, contract_addr: &str, abi_path: P) -> Result<()>
    where
        P: AsRef<Path> + Copy,
    {
        let inner = &mut self.inner.write();
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        inner.set_contract_addr(contract_info)?;

        Ok(())
    }

    pub fn deploy(
        &self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        inner.deploy(deploy_user, access_right)
    }

    pub fn register<P: AsRef<Path> + Copy>(
        &self,
        signer: SignerAddress,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        inner.register(signer, gas, contract_info)
    }

    pub fn state_transition<ST, P>(
        &self,
        access_right: AccessRight,
        state: ST,
        state_id: u64,
        call_name: &str,
        signer: SignerAddress,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String>
    where
        ST: State,
        P: AsRef<Path> + Copy,
    {
        let mut inner = self.inner.write();
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        let state_info = StateInfo::new(state, state_id, call_name);

        inner.state_transition(access_right, signer, state_info, contract_info, gas)
    }

    pub fn block_on_event<P: AsRef<Path> + Copy>(
        &self,
        contract_addr: &str,
        abi_path: P
    ) -> Result<()> {
        let mut inner = self.inner.write();
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        inner.block_on_event(contract_info)
    }

    pub fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.inner.read().get_account(index)
    }
}

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

    fn set_contract_addr<P>(
        &mut self,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<()>
    where
        P: AsRef<Path> + Copy
    {
        let enclave_id = self.deployer.get_enclave_id();
        let node_url = self.deployer.get_node_url();
        let sender = S::new(enclave_id, node_url, contract_info)?;
        let watcher = W::new(node_url, contract_info, self.event_db.clone())?;

        self.sender = Some(sender);
        self.watcher = Some(watcher);

        Ok(())
    }

    fn deploy(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
    ) -> Result<String> {
        self.deployer.deploy(deploy_user, access_right, reg_fn)
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.deployer.get_account(index)
    }

    fn block_on_event<P: AsRef<Path> + Copy>(
        &mut self,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<()> {
        // If contract address is not set, set new contract address and abi path to generate watcher instance.
        // if let None = self.watcher.as_mut() {
            self.set_contract_addr(contract_info)?;
        // }

        let eid = self.deployer.get_enclave_id();
        self.watcher.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set."))?
            .block_on_event(eid, insert_fn)
    }

    fn register<P: AsRef<Path> + Copy>(
        &mut self,
        signer: SignerAddress,
        gas: u64,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<String> {
        self.set_contract_addr(contract_info)?;

        self.sender.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set collectly."))?
            .register(signer, gas, reg_fn)
    }

    fn state_transition<ST, P>(
        &mut self,
        access_right: AccessRight,
        signer: SignerAddress,
        state_info: StateInfo<'_, ST>,
        contract_info: ContractInfo<'_, P>,
        gas: u64,
    ) -> Result<String>
    where
        ST: State,
        P: AsRef<Path> + Copy,
    {
        // If contract address is not set, set new contract address and abi path to generate sender instance.
        // if let None = self.sender.as_mut() {
            self.set_contract_addr(contract_info)?;
        // }

        self.sender.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set collectly."))?
            .state_transition(access_right, signer, state_info, gas, st_fn)
    }
}

/// A type of transaction signing address
#[derive(Debug, Clone)]
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

        /// Deploying contract with attestation.
        fn deploy<F>(
            &mut self,
            deploy_user: &SignerAddress,
            access_right: &AccessRight,
            reg_fn: F,
        ) -> Result<String>
        where
            F: FnOnce(sgx_enclave_id_t) -> Result<RawRegisterTx>;

        fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind>;

        fn get_enclave_id(&self) -> sgx_enclave_id_t;

        fn get_node_url(&self) -> &str;
    }

    /// A trait for sending transactions to blockchain nodes
    pub trait Sender: Sized {
        fn new<P: AsRef<Path>>(
            enclave_id: sgx_enclave_id_t,
            node_url: &str,
            contract_info: ContractInfo<'_, P>,
        ) -> Result<Self>;

        fn from_contract(
            enclave_id: sgx_enclave_id_t,
            contract: ContractKind,
        ) -> Self;

        fn get_account(&self, index: usize) -> Result<SignerAddress>;

        /// Send ciphertexts which is result of the state transition to blockchain nodes.
        fn state_transition<ST, F>(
            &self,
            access_right: AccessRight,
            signer: SignerAddress,
            state_info: StateInfo<'_, ST>,
            gas: u64,
            st_fn: F,
        ) -> Result<String>
        where
            ST: State,
            F: FnOnce(sgx_enclave_id_t, AccessRight, StateInfo<'_, ST>) -> Result<RawStateTransTx>;

        /// Attestation with deployed contract.
        fn register<F>(
            &self,
            signer: SignerAddress,
            gas: u64,
            reg_fn: F,
        ) -> Result<String>
        where
            F: FnOnce(sgx_enclave_id_t) -> Result<RawRegisterTx>;

        fn get_contract(self) -> ContractKind;
    }

    /// A trait of fetching event from blockchian nodes
    pub trait Watcher: Sized {
        type WatcherDB: BlockNumDB;

        fn new<P: AsRef<Path>>(
            node_url: &str,
            contract_info: ContractInfo<'_, P>,
            event_db: Arc<Self::WatcherDB>,
        ) -> Result<Self>;

        /// Blocking event fetch from blockchain nodes.
        fn block_on_event<F>(
            &self,
            eid: sgx_enclave_id_t,
            insert_fn: F,
        ) -> Result<()>
        where
            F: FnOnce(sgx_enclave_id_t, &InnerEnclaveLog) -> Result<()>;

        fn get_contract(self) -> ContractKind;
    }
}
