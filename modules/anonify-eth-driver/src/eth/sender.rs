use super::connection::{Web3Contract, Web3Http};
use crate::{error::Result, traits::*, utils::*, workflow::*};
use async_trait::async_trait;
use sgx_types::sgx_enclave_id_t;
use std::path::Path;
use web3::types::{Address, H256};

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: Web3Contract,
}

#[async_trait]
impl Sender for EthSender {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EthSender {
            enclave_id,
            contract,
        })
    }

    fn from_contract(enclave_id: sgx_enclave_id_t, contract: ContractKind) -> Self {
        match contract {
            ContractKind::Web3Contract(contract) => EthSender {
                enclave_id,
                contract,
            },
        }
    }

    async fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.contract.get_account(index, password).await
    }

    async fn send_report_handshake(
        &self,
        host_output: host_output::JoinGroup,
        method: &str,
    ) -> Result<H256> {
        self.contract
            .send_report_handshake(host_output, method)
            .await
    }

    async fn send_instruction(&self, host_output: host_output::Instruction) -> Result<H256> {
        self.contract.send_instruction(host_output).await
    }

    async fn handshake(&self, host_output: host_output::Handshake) -> Result<H256> {
        self.contract.handshake(host_output).await
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}
