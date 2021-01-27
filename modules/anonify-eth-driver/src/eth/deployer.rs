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
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http,
    address: Option<Address>, // contract address
}

#[async_trait]
impl Deployer for EthDeployer {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(node_url)?;

        Ok(EthDeployer {
            enclave_id,
            web3_conn,
            address: None,
        })
    }

    async fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        Retry::new(
            "get_account",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(deployer_retry_condition)
        .spawn_async(|| async { self.web3_conn.get_account(index, password).await })
        .await
    }

    async fn deploy<P>(
        &mut self,
        host_output: &host_output::JoinGroup,
        abi_path: P,
        bin_path: P,
        confirmations: usize,
    ) -> Result<String>
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

        self.address = Some(contract_addr);

        Ok(hex::encode(contract_addr.as_bytes()))
    }

    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind> {
        let addr = self
            .address
            .expect("The contract hasn't be deployed yet.")
            .to_string();
        let contract_info = ContractInfo::new(abi_path, &addr);
        Ok(ContractKind::Web3Contract(Web3Contract::new(
            self.web3_conn,
            contract_info,
        )?))
    }

    fn get_enclave_id(&self) -> sgx_enclave_id_t {
        self.enclave_id
    }

    fn get_node_url(&self) -> &str {
        &self.web3_conn.get_eth_url()
    }
}
