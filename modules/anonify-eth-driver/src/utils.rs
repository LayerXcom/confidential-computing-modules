use crate::{error::Result, eth::connection::Web3Contract};
use anyhow::anyhow;
use ethabi::Contract as ContractABI;
use frame_common::traits::Keccak256;
use std::{fs, io::BufReader, path::Path, str::FromStr};
use web3::types::Address;

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
/// Returns the smart contract address genereted by the CREATE2 operation,
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

/// A type of contract
pub enum ContractKind {
    Web3Contract(Web3Contract),
}
