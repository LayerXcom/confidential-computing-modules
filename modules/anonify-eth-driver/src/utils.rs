use crate::{error::Result, eth::connection::Web3Contract};
use anonify_ecall_types::*;
use anyhow::anyhow;
use ethabi::Contract as ContractABI;
use frame_common::traits::*;
use frame_treekem::EciesCiphertext;
use std::{fs::File, io::BufReader, marker::PhantomData, path::Path, str::FromStr};
use web3::types::Address;

/// Needed information to handle smart contracts.
#[derive(Debug, Clone, Copy)]
pub struct ContractInfo<'a, P: AsRef<Path>> {
    abi_path: P,
    addr: &'a str,
}

impl<'a, P: AsRef<Path>> ContractInfo<'a, P> {
    pub fn new(abi_path: P, addr: &'a str) -> Self {
        ContractInfo { abi_path, addr }
    }

    pub fn contract_abi(&self) -> Result<ContractABI> {
        let f = File::open(&self.abi_path)?;
        let reader = BufReader::new(f);

        ContractABI::load(reader)
            .map_err(|e| anyhow!("Failed to load contract abi.: {:?}", e))
            .map_err(Into::into)
    }

    pub fn address(&self) -> Result<Address> {
        Address::from_str(self.addr)
            .map_err(|e| anyhow!("{:?}", e))
            .map_err(Into::into)
    }
}

/// A type of contract
pub enum ContractKind {
    Web3Contract(Web3Contract),
}
