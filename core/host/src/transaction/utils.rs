use std::{
    path::Path,
    io::BufReader,
    fs::File,
    str::FromStr,
};
use web3::types::Address;
use ethabi::Contract as ContractABI;
use anonify_common::{AccessRight, State, call_name_to_id};
use sgx_types::sgx_enclave_id_t;
use crate::{
    bridges::ecalls::get_state,
    error::Result,
};

pub fn get_state_by_access_right<S: State>(
    access_right: &AccessRight,
    enclave_id: sgx_enclave_id_t,
) -> Result<S> {
    let state = get_state(
        enclave_id,
        &access_right.sig(),
        &access_right.pubkey(),
        &access_right.challenge(),
    )?;

    Ok(state)
}

#[derive(Debug, Clone, Copy)]
pub struct ContractInfo<'a, P: AsRef<Path>> {
    abi_path: P,
    addr: &'a str,
}

impl<'a, P: AsRef<Path>> ContractInfo<'a, P> {
    pub fn new(abi_path: P, addr: &'a str) -> Self {
        ContractInfo {
            abi_path,
            addr,
        }
    }

    pub fn contract_abi(&self) -> Result<ContractABI> {
         let f = File::open(&self.abi_path)?;
        let reader = BufReader::new(f);
        let contract_abi = ContractABI::load(reader)
            .expect("Failed to load contract abi.");

        Ok(contract_abi)
    }

    pub fn address(&self) -> Result<Address> {
        let res = Address::from_str(self.addr)?;
        Ok(res)
    }
}

pub struct StateInfo<'a, ST: State> {
    state: ST,
    state_id: u64,
    call_name: &'a str,
}

impl<'a, ST: State> StateInfo<'a, ST> {
    pub fn new(state: ST, state_id: u64, call_name: &'a str) -> Self {
        StateInfo {
            state,
            state_id,
            call_name,
        }
    }

    pub fn state_as_bytes(&self) -> Vec<u8> {
        self.state.as_bytes()
    }

    pub fn call_name_to_id(&self) -> u32 {
        call_name_to_id(&self.call_name)
    }

    pub fn state_id(&self) -> u64 {
        self.state_id
    }
}
