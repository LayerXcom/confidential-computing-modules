use super::connection::{Web3Contract, Web3Http};
use crate::{error::Result, traits::*, utils::*, workflow::*};
use async_trait::async_trait;
use sgx_types::sgx_enclave_id_t;
use std::{marker::Send, path::Path};
use web3::types::Address;

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
        self.web3_conn.get_account(index, password).await
    }

    async fn deploy<P: AsRef<Path> + Send>(
        &mut self,
        host_output: host_output::JoinGroup,
        abi_path: P,
        bin_path: P,
        confirmations: usize,
    ) -> Result<String> {
        let contract_addr = self
            .web3_conn
            .deploy(host_output, abi_path, bin_path, confirmations)
            .await?;
        self.address = Some(contract_addr);

        Ok(hex::encode(contract_addr.as_bytes()))
    }

    // TODO: generalize, remove abi.
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
