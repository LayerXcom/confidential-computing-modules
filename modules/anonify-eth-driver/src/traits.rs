#![allow(dead_code)]

use crate::{
    cache::EventCache, error::Result, eth::connection::Web3Contract, utils::*, workflow::*,
};

use async_trait::async_trait;
use sgx_types::sgx_enclave_id_t;
use web3::types::{Address, H256};

/// A trait for sending transactions to blockchain nodes
#[async_trait]
pub trait Sender: Sized + Send + Sync + 'static {
    fn new(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo,
    ) -> Result<Self>;

    fn from_contract(enclave_id: sgx_enclave_id_t, contract: Web3Contract) -> Self;

    async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address>;

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

    fn get_contract(&self) -> &Web3Contract;
}

/// A trait of fetching event from blockchian nodes
#[async_trait]
pub trait Watcher: Sized + Send + Sync + 'static {
    fn new(node_url: &str, contract_info: ContractInfo, cache: EventCache) -> Result<Self>;

    /// Blocking event fetch from blockchain nodes.
    async fn fetch_events(
        &self,
        eid: sgx_enclave_id_t,
        fetch_ciphertext_cmd: u32,
        fetch_handshake_cmd: u32,
    ) -> Result<Option<Vec<serde_json::Value>>>;

    fn get_contract(self) -> Web3Contract;
}
