use std::sync::Arc;
use crate::error::*;

use web3::{
    Web3,
    transports::{EventLoopHandle, Http},
    contract::{Contract, Options},
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256},
};

#[derive(Debug)]
pub struct AnonymousErc20Contract {
    web3: Arc<Web3<Http>>,
    eloop: EventLoopHandle,
    contract: Contract<Http>,
    account: Address,
}

// impl AnonymousErc20Contract {
//     pub fn from_deployed<P: AsRef<path>>(
//         contract_address: &str,
//         abi_path: P,

//     )
// }

// pub trait Erc20Gets {
//     fn get_balances(&self, offset: U256, len: U256) -> Result<Vec<String>>;
// }

// pub trait Erc20Posts<G> {
//     fn tranfer(&self, update_balance: String, report: String, signature: String, gas: G, confirmations: usize) -> Result<TransactionReceipt>;
// }
