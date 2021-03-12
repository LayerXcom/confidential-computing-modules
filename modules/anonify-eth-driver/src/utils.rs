use crate::{error::Result, eth::connection::Web3Contract};
use anyhow::anyhow;
use ethabi::Contract as ContractABI;
use std::{fs, io::BufReader, path::Path, str::FromStr};
use web3::types::Address;

/// Needed information to handle smart contracts.
#[derive(Debug, Clone)]
pub struct ContractInfo {
    abi: Vec<u8>,
    addr: Address,
    bin: Option<Vec<u8>>,
}

impl ContractInfo {
    pub fn new<P: AsRef<Path> + Copy>(abi_path: P, addr: Address) -> Result<Self> {
        let abi = fs::read(abi_path)?;
        Ok(ContractInfo { abi, addr, bin: None })
    }

    pub fn set_bin<P: AsRef<Path> + Copy>(mut self, bin_path: P) -> Result<Self> {
        let bin = fs::read(bin_path)?;
        self.bin = Some(bin);
        Ok(self)
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

/// A type of contract
pub enum ContractKind {
    Web3Contract(Web3Contract),
}
