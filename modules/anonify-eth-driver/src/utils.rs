use crate::{error::Result, eth::connection::Web3Contract};
use anonify_io_types::*;
use anyhow::anyhow;
use ethabi::Contract as ContractABI;
use frame_common::{state_types::StateType, traits::*};
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

#[derive(Debug, Clone)]
pub struct StateInfo<'a, ST: State, C: CallNameConverter> {
    state: ST,
    call_name: &'a str,
    phantom: PhantomData<C>,
}

impl<'a, ST: State, C: CallNameConverter> StateInfo<'a, ST, C> {
    pub fn new(state: ST, call_name: &'a str) -> Self {
        StateInfo {
            state,
            call_name,
            phantom: PhantomData::<C>,
        }
    }

    pub fn call_name_to_id(&self) -> u32 {
        C::as_id(self.call_name)
    }

    pub fn crate_input<AP: AccessPolicy>(self, access_policy: AP) -> input::Instruction<AP> {
        let call_id = self.call_name_to_id();
        let state = StateType::new(self.state.encode_s());

        input::Instruction::new(access_policy, state, call_id)
    }
}

/// A type of contract
pub enum ContractKind {
    Web3Contract(Web3Contract),
}
