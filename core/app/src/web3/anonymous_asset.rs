use std::sync::Arc;
use crate::error::*;

use web3::{
    Web3,
    transports::{EventLoopHandle, Http},
    contract::{Contract, Options},
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256},
};

#[derive(Debug)]
pub struct AnonymousAssetContract {
    web3: Arc<Web3<Http>>,
    eloop: EventLoopHandle,
    contract: Contract<Http>,
    deployer: Address,
}

impl AnonymousAssetContract {
    pub fn deploy<P: AsRef<Path>>(
        abi_path: P,
        eth_url: &str,
        deployer: Option<&str>,
    ) -> Result<Self> {
        unimplemented!();
    }

    pub fn from_deployed<P: AsRef<path>>(
        contract_address: &str,
        abi_path: P,
        deployer: Option<&str>,
        eth_url: &str,
    ) -> Result<Self> {
        unimplemented!();
    }
}

pub trait Gets {
    fn get_balances(&self, offset: U256, len: U256) -> Result<Vec<String>>;
}

impl Gets for AnonymousAssetContract {
    fn get_balances(&self, offset: U256, len: U256) -> Result<Vec<String>> {
        unimplemented!();
    }
}

pub trait Posts<G> {
    fn tranfer(&self, update_balance: String, report: String, signature: String, gas: G, confirmations: usize) -> Result<TransactionReceipt>;
}

impl<G: Into<U256>> Posts for AnonymousAssetContract {
    fn tranfer(
        &self,
        update_balance: String,
        report: String,
        sig: String,
        gas: G,
        confirmations: usize
    ) -> Result<TransactionReceipt> {
        unimplemented!();
    }
}
