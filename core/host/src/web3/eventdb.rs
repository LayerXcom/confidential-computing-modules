use anonify_common::kvs::{KVS, MemoryKVS, DBValue, DBTx};
use ethabi::Hash;
use web3::types::BlockNumber;
use byteorder::{LittleEndian, ByteOrder};
use crate::error::Result;

#[derive(Debug)]
pub struct EventDB(MemoryKVS);

impl EventDB {
    pub fn new() -> Self {
        EventDB(MemoryKVS::new())
    }

    pub fn set_latest_block_num(&self, tx: EventDBTx) {
        self.0.inner_write(tx.0)
    }

    pub fn get_latest_block_num(&self, key: Hash) -> BlockNumber {
        let db_value = self.0.inner_get(key.as_bytes())
            .unwrap_or(DBValue::default());
        let blk_num = LittleEndian::read_u64(&db_value.into_vec());

        BlockNumber::Number(blk_num)
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
