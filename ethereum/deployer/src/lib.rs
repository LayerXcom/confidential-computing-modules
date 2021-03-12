use anonify_eth_driver::{
    error::{HostError, Result},
    eth::{sender::sender_retry_condition, Web3Http},
    utils::{calc_anonify_contract_address, deployer_retry_condition, get_account, ContractInfo},
};
use frame_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use frame_retrier::{strategy, Retry};
use std::{marker::Send, path::Path};
use web3::{
    contract::{Contract, Options},
    types::{Address, H256},
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

    pub async fn deploy_anonify_by_create2<P>(
        &self,
        abi_path: P,
        signer: Address,
        gas: u64,
        salt: [u8; 32],
        create2_address: Address,
    ) -> Result<H256>
    where
        P: AsRef<Path> + Send + Sync + Copy,
    {
        let contract_info = ContractInfo::new(abi_path, create2_address)?;
        let abi = contract_info.contract_abi()?;
        let contract = Contract::new(self.web3_conn.web3.eth(), contract_info.address(), abi);

        Retry::new(
            "deploy",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(sender_retry_condition)
        .spawn_async(|| async {
            contract
                .call(
                    "deploy",
                    salt,
                    signer,
                    Options::with(|opt| opt.gas = Some(gas.into())),
                )
                .await
                .map_err(Into::into)
        })
        .await
    }
}
