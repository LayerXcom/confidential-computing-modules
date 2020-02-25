#![allow(dead_code)]

use std::{
    path::Path,
    sync::Arc,
    convert::{TryInto, TryFrom},
    fmt::Debug,
};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use anonify_types::{RawRegisterTx, RawStateTransTx};
use anonify_common::{AccessRight, UserAddress};
use anonify_runtime::State;
use super::{
    eth::primitives::Web3Contract,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    utils::{ContractInfo, StateInfo},
    sgx_dispatcher::{SgxDispatcher, get_state_sgx},
};
use crate::error::{Result, HostErrorKind};
use self::traits::*;

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    inner: RwLock<SgxDispatcher<D,S,W,DB>>,
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
        let inner = SgxDispatcher::new_with_deployer(enclave_id, node_url, event_db)?;

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

pub fn get_state<S>(
    access_right: &AccessRight,
    enclave_id: sgx_enclave_id_t,
    mem_name: &str,
) -> Result<S>
where
    S: State + TryFrom<Vec<u8>>,
    <S as TryFrom<Vec<u8>>>::Error: Debug,
{
    get_state_sgx(access_right, enclave_id, mem_name)
}
