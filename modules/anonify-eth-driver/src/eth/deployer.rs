use super::primitives::{Web3Contract, Web3Http};
use crate::{error::Result, traits::*, utils::*, workflow::*};
use sgx_types::sgx_enclave_id_t;
use std::path::Path;
use web3::types::Address;

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http,
    address: Option<Address>, // contract address
}

impl Deployer for EthDeployer {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(node_url)?;

        Ok(EthDeployer {
            enclave_id,
            web3_conn,
            address: None,
        })
    }

    fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.web3_conn.get_account(index, password)
    }

    fn deploy<P: AsRef<Path>>(
        &mut self,
        host_output: host_output::JoinGroup,
        confirmations: usize,
        abi_path: P,
        bin_path: P,
    ) -> Result<String> {
        let contract_addr =
            self.web3_conn
                .deploy(host_output, confirmations, abi_path, bin_path)?;
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
