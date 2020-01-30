use std::path::Path;
use sgx_types::sgx_enclave_id_t;
use anonify_common::{AccessRight, State};
use web3::types::H160;
use super::eth::primitives::Web3Contract;
use crate::error::Result;

pub struct Dispatcher<D: Deployer> {
    deployer: D,
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

pub enum SignerAddress {
    EthAddress(web3::types::Address)
}

pub enum ContractKind {
    Web3Contract(Web3Contract)
}
