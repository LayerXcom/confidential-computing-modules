use anonify_eth_driver::{
    error::{HostError, Result},
    eth::Web3Http,
};
use frame_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use frame_retrier::{strategy, Retry};
use std::{marker::Send, path::Path};
use web3::types::Address;

/// Define a retry condition of deploying contracts.
/// If it returns true, retry deploying contracts.
const fn deployer_retry_condition(res: &Result<Address>) -> bool {
    match res {
        Ok(_) => false,
        Err(err) => match err {
            HostError::Web3ContractError(web3_err) => match web3_err {
                web3::contract::Error::Abi(_) => false,
                _ => true,
            },
            HostError::Web3ContractDeployError(web3_err) => match web3_err {
                web3::contract::deploy::Error::Abi(_) => false,
                _ => true,
            },
            HostError::EcallOutputNotSet => false,
            // error reading abi and bin path
            HostError::IoError(_) => false,
            _ => true,
        },
    }
}

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    web3_conn: Web3Http,
}

impl EthDeployer {
    fn new(node_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(node_url)?;

        Ok(EthDeployer { web3_conn })
    }

    async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        Retry::new(
            "get_account",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(deployer_retry_condition)
        .spawn_async(|| async { self.web3_conn.get_account(index, password).await })
        .await
    }

    async fn deploy<P>(&self, abi_path: P, bin_path: P, confirmations: usize) -> Result<String>
    where
        P: AsRef<Path> + Send + Sync + Copy,
    {
        let contract_addr = Retry::new(
            "deploy",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(deployer_retry_condition)
        .spawn_async(|| async {
            self.web3_conn
                .deploy(host_output.clone(), abi_path, bin_path, confirmations)
                .await
        })
        .await?;

        Ok(hex::encode(contract_addr.as_bytes()))
    }
}
