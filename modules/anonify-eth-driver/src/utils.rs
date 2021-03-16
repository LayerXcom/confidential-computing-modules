use crate::{
    error::{HostError, Result},
    eth::{connection::Web3Contract, sender::sender_retry_condition},
    Web3Http,
};
use anyhow::anyhow;
use ethabi::Contract as ContractABI;
use frame_common::traits::Keccak256;
use frame_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use frame_retrier::{strategy, Retry};
use std::{fs, io::BufReader, path::Path, str::FromStr};
use web3::{contract::Contract, transports::Http, types::Address};

/// Define a retry condition of deploying contracts.
/// If it returns true, retry deploying contracts.
pub const fn deployer_retry_condition(res: &Result<Address>) -> bool {
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

/// Needed information to handle smart contracts.
#[derive(Debug, Clone)]
pub struct ContractInfo {
    abi: Vec<u8>,
    addr: Address,
}

impl ContractInfo {
    pub fn new<P: AsRef<Path> + Copy>(abi_path: P, addr: Address) -> Result<Self> {
        let abi = fs::read(abi_path)?;
        Ok(ContractInfo { abi, addr })
    }

    pub fn contract_abi(&self) -> Result<ContractABI> {
        ContractABI::load(&self.abi[..])
            .map_err(|e| anyhow!("Failed to load contract abi.: {:?}", e))
            .map_err(Into::into)
    }

    pub fn address(&self) -> Address {
        self.addr
    }
}

/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1014.md
/// Returns the smart contract address genereted by the FACTORY operation,
/// keccak256( 0xff ++ address ++ salt ++ keccak256(init_code))[12:]
pub fn calc_anonify_contract_address(sender: Address, salt: [u8; 32], bin_code: &[u8]) -> Address {
    let bytes = [
        &[0xff],
        sender.as_bytes(),
        salt.as_ref(),
        &bin_code.keccak256(),
    ]
    .concat();
    let hash = &bytes.keccak256();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address::from(addr)
}

pub async fn get_account(
    web3_conn: &Web3Http,
    index: usize,
    password: Option<&str>,
) -> Result<Address> {
    Retry::new(
        "get_account",
        *REQUEST_RETRIES,
        strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
    )
    .set_condition(deployer_retry_condition)
    .spawn_async(|| async { web3_conn.get_account(index, password).await })
    .await
}

pub fn create_contract_interface<P: AsRef<Path> + Copy>(
    node_url: &str,
    abi_path: P,
    contracrt_address: Address,
) -> Result<Contract<Http>> {
    let web3_conn = Web3Http::new(node_url)?;
    let contract_info = ContractInfo::new(abi_path, contracrt_address)?;
    let abi = contract_info.contract_abi()?;

    Ok(Contract::new(
        web3_conn.web3.eth(),
        contract_info.address(),
        abi,
    ))
}
