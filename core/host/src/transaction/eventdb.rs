use std::sync::Arc;
use anonify_common::{
    Ciphertext,
    kvs::{KVS, MemoryDB, DBTx}
};
use ethabi::Hash;
use sgx_types::sgx_enclave_id_t;
use byteorder::{LittleEndian, ByteOrder};
use crate::error::Result;

pub trait BlockNumDB {
    fn new() -> Self;

    fn set_next_block_num(&self, tx: EventDBTx);

    fn get_latest_block_num(&self, key: Hash) -> u64;
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

    fn get_latest_block_num(&self, key: Hash) -> u64 {
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

    pub fn put(&mut self, event_hash: Hash, block_num: u64) {
        let mut wtr = [0u8; 8];
        LittleEndian::write_u64(&mut wtr, block_num);
        self.0.put(event_hash.as_bytes(), &wtr);
    }
}

/// A log which is sent to enclave. Each log containes ciphertexts data of a given contract address and a given block number.
#[derive(Debug, Clone)]
pub(crate) struct InnerEnclaveLog {
    pub(crate) contract_addr: [u8; 20],
    pub(crate) latest_blc_num: u64,
    pub(crate) ciphertexts: Vec<Ciphertext>, // Concatenated all fetched ciphertexts
}

/// A wrapper type of enclave logs.
#[derive(Debug, Clone)]
pub struct EnclaveLog<DB: BlockNumDB> {
    pub(crate) inner: Option<InnerEnclaveLog>,
    pub(crate) db: Arc<DB>,
}

impl<DB: BlockNumDB> EnclaveLog<DB> {
    /// Store logs into enclave in-memory.
    /// This returns a latest block number specified by fetched logs.
    pub fn insert_enclave(self, eid: sgx_enclave_id_t) -> Result<EnclaveBlockNumber<DB>> {
        use crate::ecalls::insert_logs;
        match &self.inner {
            Some(log) => {
                insert_logs(eid, log)?;
                let next_blc_num = log.latest_blc_num + 1;

                return Ok(EnclaveBlockNumber {
                    inner: Some(next_blc_num),
                    db: self.db,
                });
            },
            None => return Ok(EnclaveBlockNumber {
                inner: None,
                db: self.db,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnclaveBlockNumber<DB: BlockNumDB> {
    inner: Option<u64>,
    db: Arc<DB>,
}

impl<DB: BlockNumDB> EnclaveBlockNumber<DB> {
    /// Only if EnclaveBlockNumber has new block number to log,
    /// it's set next block number to event db.
    pub fn set_to_db(&self, key: Hash) {
        match &self.inner {
            Some(num) => {
                let mut dbtx = EventDBTx::new();
                dbtx.put(key, *num);
                self.db.set_next_block_num(dbtx);
            },
            None => { },
        }
    }
}
