#![allow(dead_code)]

use std::{
    path::Path,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use frame_common::{
    traits::*,
    state_types::UpdatedState,
};
use anonify_io_types::*;
use web3::types::{Address, TransactionReceipt};
use crate::{
    error::Result,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    utils::*,
    workflow::*,
};

/// A trait for deploying contracts
pub trait Deployer: Sized {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self>;

    fn get_account(&self, index: usize, password: &str) -> Result<Address>;

    /// Deploying contract with attestation.
    fn deploy<P: AsRef<Path>>(
        &mut self,
        host_output: host_output::JoinGroup,
        confirmations: usize,
        abi_path: P,
        bin_path: P,
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
        contract_info: ContractInfo<'_, P>,
    ) -> Result<Self>;

    fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: ContractKind,
    ) -> Self;

    fn get_account(&self, index: usize, password: &str) -> Result<Address>;

    /// Send an encrypted instruction of state transition to blockchain nodes.
    fn send_instruction(
        &self,
        host_output: host_output::Instruction,
        confirmations: usize,
    ) -> Result<TransactionReceipt>;

    /// Attestation with deployed contract.
    fn join_group(
        &self,
        host_output: host_output::JoinGroup,
        confirmations: usize,
    ) -> Result<TransactionReceipt>;

    fn handshake(
        &self,
        host_output: host_output::Handshake,
        confirmations: usize,
    ) -> Result<TransactionReceipt>;

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
    fn block_on_event<S: State>(
        &self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>>;

    fn get_contract(self) -> ContractKind;
}
