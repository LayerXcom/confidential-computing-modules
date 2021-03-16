use anonify_eth_driver::{
    error::{HostError, Result},
    eth::{sender::sender_retry_condition, Web3Http},
    utils::*,
};
use frame_config::{
    ANONIFY_ABI_PATH, ANONIFY_BIN_PATH, FACTORY_BIN_PATH, REQUEST_RETRIES, RETRY_DELAY_MILLS,
};
use frame_retrier::{strategy, Retry};
use std::{fs, marker::Send, path::Path};
use web3::{
    contract::{Contract, Options},
    types::{Address, TransactionReceipt, H256},
};

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    web3_conn: Web3Http,
}

impl EthDeployer {
    pub fn new(node_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(node_url)?;

        Ok(EthDeployer { web3_conn })
    }

    pub async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        get_account(&self.web3_conn, index, password).await
    }

    pub async fn deploy<P>(
        &self,
        abi_path: P,
        bin_path: P,
        confirmations: usize,
        gas: u64,
        deployer: Address,
    ) -> Result<Address>
    where
        P: AsRef<Path> + Send + Sync + Copy,
    {
        Retry::new(
            "deploy",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(deployer_retry_condition)
        .spawn_async(|| async {
            self.web3_conn
                .deploy(abi_path, bin_path, confirmations, gas, deployer)
                .await
        })
        .await
        .map_err(Into::into)
    }

    pub async fn deploy_anonify_by_factory<P>(
        &self,
        abi_path: P,
        signer: Address,
        gas: u64,
        factory_address: Address,
        confirmations: usize,
    ) -> Result<TransactionReceipt>
    where
        P: AsRef<Path> + Send + Sync + Copy,
    {
        let contract =
            create_contract_interface(self.web3_conn.get_eth_url(), abi_path, factory_address)?;

        Retry::new(
            "deploy",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(deploy_with_conf_retry_condition)
        .spawn_async(|| async {
            contract
                .call_with_confirmations(
                    "deploy",
                    (),
                    signer,
                    Options::with(|opt| opt.gas = Some(gas.into())),
                    confirmations,
                )
                .await
                .map_err(Into::into)
        })
        .await
    }
}

pub const fn deploy_with_conf_retry_condition(res: &Result<TransactionReceipt>) -> bool {
    match res {
        Ok(_) => false,
        Err(_err) => false,
    }
}
