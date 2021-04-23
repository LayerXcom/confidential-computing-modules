use super::connection::{Web3Contract, Web3Http};
use crate::{error::Result, utils::*, workflow::*};
use frame_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use frame_retrier::{strategy, Retry};
use sgx_types::sgx_enclave_id_t;
use tracing::info;
use web3::types::{Address, TransactionReceipt, H256};

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: Web3Contract,
}

impl EthSender {
    pub fn new(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo,
        confirmations: usize,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info, confirmations)?;

        Ok(EthSender {
            enclave_id,
            contract,
        })
    }

    pub fn from_contract(enclave_id: sgx_enclave_id_t, contract: Web3Contract) -> Self {
        EthSender {
            enclave_id,
            contract,
        }
    }

    pub async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        Retry::new(
            "get_account",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(deployer_retry_condition)
        .spawn_async(|| async { self.contract.get_account(index, password).await })
        .await
    }

    pub async fn send_report_handshake(
        &self,
        host_output: &host_output::JoinGroup,
        method: &str,
    ) -> Result<TransactionReceipt> {
        info!("Sending a handshake to blockchain: {:?}", host_output);
        Retry::new(
            "send_report_handshake",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(call_with_conf_retry_condition)
        .spawn_async(|| async {
            self.contract
                .send_report_handshake(host_output.clone(), method)
                .await
        })
        .await
    }

    pub async fn register_report(&self, host_output: &host_output::RegisterReport) -> Result<H256> {
        info!("Registering report to blockchain: {:?}", host_output);
        Retry::new(
            "send_command",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(sender_retry_condition)
        .spawn_async(|| async { self.contract.register_report(host_output.clone()).await })
        .await
    }

    pub async fn send_command(&self, host_output: &host_output::Command) -> Result<H256> {
        info!("Sending a command to blockchain: {:?}", host_output);
        Retry::new(
            "send_command",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(sender_retry_condition)
        .spawn_async(|| async { self.contract.send_command(host_output.clone()).await })
        .await
    }

    pub async fn handshake(&self, host_output: &host_output::Handshake) -> Result<H256> {
        info!("Sending a handshake to blockchain: {:?}", host_output);
        Retry::new(
            "handshake",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(sender_retry_condition)
        .spawn_async(|| async { self.contract.handshake(host_output.clone()).await })
        .await
    }

    pub fn get_contract(&self) -> &Web3Contract {
        &self.contract
    }
}
