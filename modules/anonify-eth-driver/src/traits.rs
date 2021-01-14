#![allow(dead_code)]

use crate::{cache::EventCache, error::Result, utils::*, workflow::*};

use async_trait::async_trait;
use frame_common::{state_types::UpdatedState, traits::*};
use sgx_types::sgx_enclave_id_t;
use std::{marker::Send, path::Path};
use web3::types::{Address, H256};

/// A trait for deploying contracts
#[async_trait]
pub trait Deployer: Sized {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self>;

    async fn get_account(&self, index: usize, password: &str) -> Result<Address>;

    /// Deploying contract with attestation.
    async fn deploy<P>(
        &mut self,
        host_output: &host_output::JoinGroup,
        abi_path: P,
        bin_path: P,
        confirmations: usize,
    ) -> Result<String>
    where
        P: AsRef<Path> + Send + Sync + Copy;

    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind>;

    fn get_enclave_id(&self) -> sgx_enclave_id_t;

    fn get_node_url(&self) -> &str;
}

/// A trait for sending transactions to blockchain nodes
#[async_trait]
pub trait Sender: Sized {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<Self>;

    fn from_contract(enclave_id: sgx_enclave_id_t, contract: ContractKind) -> Self;

    async fn get_account(&self, index: usize, password: &str) -> Result<Address>;

    /// Send an encrypted command of state transition to blockchain nodes.
    async fn send_command(&self, host_output: &host_output::Command) -> Result<H256>;

    /// Attestation with deployed contract.
    async fn send_report_handshake(
        &self,
        host_output: &host_output::JoinGroup,
        method: &str,
    ) -> Result<H256>;

    async fn register_report(&self, host_output: &host_output::RegisterReport) -> Result<H256>;

    async fn handshake(&self, host_output: &host_output::Handshake) -> Result<H256>;

    fn get_contract(self) -> ContractKind;
}

/// A trait of fetching event from blockchian nodes
#[async_trait]
pub trait Watcher: Sized {
    fn new<P: AsRef<Path>>(
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
        cache: EventCache,
    ) -> Result<Self>;

    /// Blocking event fetch from blockchain nodes.
    async fn fetch_events<S: State>(
        &self,
        eid: sgx_enclave_id_t,
        fetch_ciphertext_cmd: u32,
        fetch_handshake_cmd: u32,
    ) -> Result<Option<Vec<UpdatedState<S>>>>;

    fn get_contract(self) -> ContractKind;
}
