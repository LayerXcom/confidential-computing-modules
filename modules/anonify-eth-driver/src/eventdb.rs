use crate::error::Result;
use crate::workflow::*;

use frame_common::{
    crypto::Ciphertext,
    state_types::UpdatedState,
    traits::State,
};
use frame_host::engine::HostEngine;
use log::debug;
use sgx_types::sgx_enclave_id_t;
use std::collections::{HashMap, HashSet};
use web3::types::Address as ContractAddr;

type BlockNum = u64;
type RosterIdx = u32;
type Epoch = u32;
type Generation = u32;

// TODO: overhead clone
#[derive(Debug, Default, Clone)]
pub struct EventCache {
    block_num_counter: HashMap<ContractAddr, BlockNum>,
    treekem_counter: HashMap<RosterIdx, (Epoch, Generation)>,
    ciphertext_pool: HashSet<Ciphertext>,
}

impl EventCache {
    pub fn insert_next_block_num(&mut self, contract_addr: ContractAddr, block_num: BlockNum) -> Option<BlockNum> {
        self.block_num_counter.insert(contract_addr, block_num)
    }

    pub fn get_latest_block_num(&self, contract_addr: ContractAddr) -> Option<BlockNum> {
        self.block_num_counter.get(&contract_addr).map(|e| *e)
    }

    pub fn is_next_msg(&self, msg: Ciphertext) -> bool {
        unimplemented!();
    }

    pub fn update_treekem_counter(&self, ciphertext: Ciphertext) {
        unimplemented!();
    }

    pub fn insert_ciphertext_pool(&self, ciphertext: Ciphertext) {
        unimplemented!();
    }

    pub fn find_ciphertext_pool(&self, ciphertext: Ciphertext) {
        unimplemented!();
    }
}


/// A log which is sent to enclave. Each log containes ciphertexts data of a given contract address and a given block number.
#[derive(Debug, Clone)]
pub struct InnerEnclaveLog {
    pub contract_addr: [u8; 20],
    pub latest_blc_num: u64,
    pub ciphertexts: Vec<Ciphertext>, // Concatenated all fetched ciphertexts
    pub handshakes: Vec<Vec<u8>>,
}

impl InnerEnclaveLog {
    #[must_use]
    pub fn verify_order(self) -> Result<Self> {
        unimplemented!();
    }

    pub fn into_input_iter(self) -> impl Iterator<Item = host_input::InsertCiphertext> {
        self.ciphertexts
            .into_iter()
            .map(host_input::InsertCiphertext::new)
    }

    pub fn invoke_ecall<S: State>(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        if !self.ciphertexts.is_empty() && self.handshakes.is_empty() {
            self.insert_ciphertexts(eid)
        } else if self.ciphertexts.is_empty() && !self.handshakes.is_empty() {
            // The size of handshake cannot be calculated in this host directory,
            // so the ecall_insert_handshake function is repeatedly called over the number of fetched handshakes.
            for handshake in self.handshakes {
                Self::insert_handshake(eid, handshake)?;
            }

            Ok(None)
        } else {
            debug!("No logs to insert into the enclave.");
            Ok(None)
        }
    }

    fn insert_ciphertexts<S: State>(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        let mut acc = vec![];

        for update in self.into_input_iter().map(
            move |inp| InsertCiphertextWorkflow::exec(inp, eid).map(|e| e.ecall_output.unwrap()), // ecall_output must be set.
        ) {
            if let Some(upd_type) = update?.updated_state {
                let upd_trait = UpdatedState::<S>::from_state_type(upd_type)?;
                acc.push(upd_trait);
            }
        }

        if acc.is_empty() {
            Ok(None)
        } else {
            Ok(Some(acc))
        }
    }

    fn insert_handshake(eid: sgx_enclave_id_t, handshake: Vec<u8>) -> Result<()> {
        let input = host_input::InsertHandshake::new(handshake);
        InsertHandshakeWorkflow::exec(input, eid)?;

        Ok(())
    }
}

/// A wrapper type of enclave logs.
#[derive(Debug)]
pub struct EnclaveLog {
    pub inner: Option<InnerEnclaveLog>,
    pub cache: EventCache,
}

impl EnclaveLog {

    #[must_use]
    pub fn verify_order(self) -> Result<Self> {
        unimplemented!();
    }

    /// Store logs into enclave in-memory.
    /// This returns a latest block number specified by fetched logs.
    pub fn insert_enclave<S: State>(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<EnclaveUpdatedState<S>> {
        match self.inner {
            Some(log) => {
                let next_blc_num = log.latest_blc_num + 1;
                let updated_states = log.invoke_ecall(eid)?;

                Ok(EnclaveUpdatedState {
                    block_num: Some(next_blc_num),
                    updated_states,
                    cache: self.cache,
                })
            }
            None => Ok(EnclaveUpdatedState {
                block_num: None,
                updated_states: None,
                cache: self.cache,
            }),
        }
    }
}

#[derive(Debug)]
pub struct EnclaveUpdatedState<S: State> {
    block_num: Option<u64>,
    updated_states: Option<Vec<UpdatedState<S>>>,
    cache: EventCache,
}

impl<S: State> EnclaveUpdatedState<S> {
    /// Only if EnclaveUpdatedState has new block number to log,
    /// it's set next block number to event cache.
    pub fn save_cache(mut self, contract_addr: ContractAddr) -> Self {
        match &self.block_num {
            Some(block_num) => {
                self.cache.insert_next_block_num(contract_addr, *block_num);
            }
            None => {}
        }

        self
    }

    pub fn updated_states(self) -> Option<Vec<UpdatedState<S>>> {
        self.updated_states
    }
}
