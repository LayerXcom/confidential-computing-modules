use super::connection::{Web3Contract, Web3Http};
use crate::{
    error::{HostError, Result},
    traits::*,
    utils::*,
    workflow::*,
};
use async_trait::async_trait;
use frame_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use frame_retrier::{strategy, Retry};
use sgx_types::sgx_enclave_id_t;
use std::path::Path;
use tracing::info;
use web3::types::{Address, H256};

/// Define a retry condition of sending transactions.
/// If it returns false, don't need to retry sending transactions.
pub const fn sender_retry_condition(res: &Result<H256>) -> bool {
    match res {
        Ok(_) => false,
        Err(err) => match err {
            HostError::Web3ContractError(web3_err) => match web3_err {
                web3::contract::Error::Abi(_) => false,
                _ => true,
            },
            HostError::EcallOutputNotSet => false,
            _ => true,
        },
    }
}

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: Web3Contract,
}

#[async_trait]
impl Sender for EthSender {
    fn new(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EthSender {
            enclave_id,
            contract,
        })
    }

    fn from_contract(enclave_id: sgx_enclave_id_t, contract: Web3Contract) -> Self {
        EthSender {
            enclave_id,
            contract,
        }
    }

    async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        Retry::new(
            "get_account",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(sender_retry_condition)
        .spawn_async(|| async { self.contract.get_account(index, password).await })
        .await
    }

    async fn send_report_handshake(
        &self,
        host_output: &host_output::JoinGroup,
        method: &str,
    ) -> Result<H256> {
        info!("Sending a handshake to blockchain: {:?}", host_output);
        Retry::new(
            "send_report_handshake",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(sender_retry_condition)
        .spawn_async(|| async {
            self.contract
                .send_report_handshake(host_output.clone(), method)
                .await
        })
        .await
    }

    async fn register_report(&self, host_output: &host_output::RegisterReport) -> Result<H256> {
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

    async fn send_command(&self, host_output: &host_output::Command) -> Result<H256> {
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

    async fn handshake(&self, host_output: &host_output::Handshake) -> Result<H256> {
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

    fn get_contract(&self) -> &Web3Contract {
        &self.contract
    }
}
