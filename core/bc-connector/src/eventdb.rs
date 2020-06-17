use std::sync::Arc;
use anonify_common::{
    kvs::{KVS, MemoryDB, DBTx}
};
use anonify_app_preluder::Ciphertext;
use anonify_runtime::{UpdatedState, traits::State};
use sgx_types::sgx_enclave_id_t;
use web3::types::Address;
use byteorder::{LittleEndian, ByteOrder};
use crate::error::Result;

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

/// A wrapper type of enclave logs.
#[derive(Debug, Clone)]
pub struct EnclaveLog<DB: BlockNumDB> {
    pub inner: Option<InnerEnclaveLog>,
    pub db: Arc<DB>,
}

impl<DB: BlockNumDB> EnclaveLog<DB> {
    /// Store logs into enclave in-memory.
    /// This returns a latest block number specified by fetched logs.
    pub fn insert_enclave<F, S>(
        self,
        eid: sgx_enclave_id_t,
        insert_fn: F,
    ) -> Result<EnclaveUpdatedState<DB, S>>
    where
        F: FnOnce(sgx_enclave_id_t, &InnerEnclaveLog) -> Result<Option<Vec<UpdatedState<S>>>>,
        S: State,
    {
        match &self.inner {
            Some(log) => {
                let updated_states = insert_fn(eid, log)?;
                let next_blc_num = log.latest_blc_num + 1;

                return Ok(EnclaveUpdatedState {
                    block_num: Some(next_blc_num),
                    updated_states: updated_states,
                    db: self.db,
                });
            },
            None => return Ok(EnclaveUpdatedState {
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
            },
            None => { },
        }

        self
    }

    pub fn updated_states(self) -> Option<Vec<UpdatedState<S>>> {
        self.updated_states
    }
}
