use std::path::Path;
use sgx_types::sgx_enclave_id_t;
use anonify_common::{AccessRight, State, UserAddress};
use web3::types::{H160, H256};
use super::eth::primitives::Web3Contract;
use crate::error::Result;

pub struct Dispatcher<D: Deployer, S: Sender> {
    deployer: D,
    sender: S,
}

pub trait Deployer: Sized {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self>;

    fn get_account(&self, index: usize) -> Result<SignerAddress>;

    fn deploy<S: State>(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
        state: S,
    ) -> Result<H160>;

    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind>;
}

pub trait Sender: Sized {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        eth_url: &str,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<Self>;

    fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: ContractKind,
    ) -> Self;

    fn get_account(&self, index: usize) -> Result<SignerAddress>;

    fn send_tx<S: State>(
        &self,
        access_right: &AccessRight,
        target: &UserAddress,
        state: S,
        from_eth_addr: SignerAddress,
        gas: u64,
    ) -> Result<H256>;

    fn get_contract(self) -> ContractKind;
}

pub enum SignerAddress {
    EthAddress(web3::types::Address)
}

pub enum ContractKind {
    Web3Contract(Web3Contract)
}
