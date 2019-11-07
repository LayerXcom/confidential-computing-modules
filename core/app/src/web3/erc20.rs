use std::sync::Arc;

use web3::{
    Web3,
    transports::{EventLoopHandle, Http},
    contract::{Contract, Options},
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256},
};

#[derive(Debug)]
pub struct Erc20Contract {
    web3: Arc<Web3<Http>>,
    eloop: EventLoopHandle,
    contract: Contract<Http>,
    account: Address,
}

// pub trait Erc20Gets {

// }

// pub trait Erc20Posts {

// }
