use crate::error::Result;
use crate::workflow::*;

use byteorder::{ByteOrder, LittleEndian};
use frame_common::{
    crypto::Ciphertext,
    kvs::{DBTx, MemoryDB, KVS},
    state_types::UpdatedState,
    traits::State,
};
use frame_host::engine::HostEngine;
use log::debug;
use sgx_types::sgx_enclave_id_t;
use std::sync::Arc;
use web3::types::Address;

pub trait BlockNumDB {
    fn new() -> Self;

    fn set_next_block_num(&self, tx: EventDBTx);

    fn get_latest_block_num(&self, key: Address) -> u64;
}

#[derive(Debug)]
pub struct EventDB(MemoryDB);

impl BlockNumDB for EventDB {
    fn new() -> Self {
        EventDB(MemoryDB::new())
    }

    fn set_next_block_num(&self, tx: EventDBTx) {
        self.0.inner_write(tx.0)
    }

    fn get_latest_block_num(&self, key: Address) -> u64 {
        match self.0.inner_get(key.as_bytes()) {
            Some(val) => LittleEndian::read_u64(&val.into_vec()),
            None => 0,
        }
    }
}

#[derive(Default, Clone, PartialEq)]
pub struct EventDBTx(DBTx);

impl EventDBTx {
    pub fn new() -> Self {
        EventDBTx(DBTx::new())
    }

    pub fn put(&mut self, address: Address, block_num: u64) {
        let mut wtr = [0u8; 8];
        LittleEndian::write_u64(&mut wtr, block_num);
        self.0.put(address.as_bytes(), &wtr);
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
#[derive(Debug, Clone)]
pub struct EnclaveLog<DB: BlockNumDB> {
    pub inner: Option<InnerEnclaveLog>,
    pub db: Arc<DB>,
}

impl<DB: BlockNumDB> EnclaveLog<DB> {
    pub fn verify_order(self) -> Result<Self> {
        unimplemented!();
    }

    /// Store logs into enclave in-memory.
    /// This returns a latest block number specified by fetched logs.
    pub fn insert_enclave<S: State>(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<EnclaveUpdatedState<DB, S>> {
        match self.inner {
            Some(log) => {
                let next_blc_num = log.latest_blc_num + 1;
                let updated_states = log.invoke_ecall(eid)?;

                Ok(EnclaveUpdatedState {
                    block_num: Some(next_blc_num),
                    updated_states,
                    db: self.db,
                })
            }
            None => Ok(EnclaveUpdatedState {
                block_num: None,
                updated_states: None,
                db: self.db,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnclaveUpdatedState<DB: BlockNumDB, S: State> {
    block_num: Option<u64>,
    updated_states: Option<Vec<UpdatedState<S>>>,
    db: Arc<DB>,
}

impl<DB: BlockNumDB, S: State> EnclaveUpdatedState<DB, S> {
    /// Only if EnclaveUpdatedState has new block number to log,
    /// it's set next block number to event db.
    pub fn set_to_db(self, key: Address) -> Self {
        match &self.block_num {
            Some(block_num) => {
                let mut dbtx = EventDBTx::new();
                dbtx.put(key, *block_num);
                self.db.set_next_block_num(dbtx);
            }
            None => {}
        }

        self
    }

    pub fn updated_states(self) -> Option<Vec<UpdatedState<S>>> {
        self.updated_states
    }
}
