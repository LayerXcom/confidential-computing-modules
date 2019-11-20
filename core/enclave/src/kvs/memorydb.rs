use std::{
    prelude::v1::*,
    sync::SgxRwLock as RwLock,
    collections::BTreeMap,
};
use anonify_types::*;
use super::*;
use super::traits::KVS;
use crate::error::Result;

pub struct MemoryKVS(RwLock<BTreeMap<Vec<u8>, DBValue>>);

impl MemoryKVS {
    pub fn new() -> Self {
        MemoryKVS(RwLock::new(BTreeMap::new()))
    }
}

impl KVS for MemoryKVS {
    fn get(&self, key: &[u8]) -> Option<DBValue> {
        let d = self.0.read().unwrap();
        d.get(key).cloned()
    }

    fn write(&self, tx: DBTx) {
        let mut d = self.0.write().unwrap();
        let ops = tx.ops;
        for op in ops {
            match op {
                DBOp::Insert { key, value } => {
                    d.insert(key.into_vec(), value);
                },
                DBOp::Delete { key } => {
                    d.remove(&*key);
                },
            }
        }
    }
}
