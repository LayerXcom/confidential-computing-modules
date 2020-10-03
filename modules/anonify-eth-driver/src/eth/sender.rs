use super::primitives::{Web3Contract, Web3Http};
use crate::{error::Result, traits::*, utils::*, workflow::*};
use sgx_types::sgx_enclave_id_t;
use std::path::Path;
use web3::types::{Address, TransactionReceipt};

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: Web3Contract,
}

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

    fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.contract.get_account(index, password)
    }

    fn send_report_handshake(
        &self,
        host_output: host_output::JoinGroup,
        confirmations: usize,
        method: &str,
    ) -> Result<TransactionReceipt> {
        self.contract
            .send_report_handshake(host_output, confirmations, method)
    }

    fn send_instruction(
        &self,
        host_output: host_output::Instruction,
        confirmations: usize,
    ) -> Result<TransactionReceipt> {
        self.contract.send_instruction(host_output, confirmations)
    }

    fn handshake(
        &self,
        host_output: host_output::Handshake,
        confirmations: usize,
    ) -> Result<TransactionReceipt> {
        self.contract.handshake(host_output, confirmations)
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}
