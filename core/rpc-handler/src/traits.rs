#![allow(dead_code)]

use std::{
    path::Path,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use anonify_types::{RawRegisterTx, RawStateTransTx};
use anonify_common::AccessRight;
use anonify_runtime::State;
use crate::{
    error::Result,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    utils::*,
};

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
