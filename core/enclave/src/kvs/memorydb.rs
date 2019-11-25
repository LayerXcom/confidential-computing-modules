use std::{
    prelude::v1::*,
    sync::SgxRwLock as RwLock,
    collections::BTreeMap,
};
use anonify_types::*;
use super::*;
use super::traits::*;
use crate::{
    error::Result,
    crypto::UserAddress,
};

lazy_static! {
    pub static ref MEMORY_DB: MemoryKVS = MemoryKVS::new();
}

pub struct MemoryKVS(RwLock<BTreeMap<Vec<u8>, DBValue>>);

impl MemoryKVS {
    pub fn new() -> Self {
        MemoryKVS(RwLock::new(BTreeMap::new()))
    }
}

impl SigVerificationKVS for MemoryKVS {
    fn get(&self, msg: &[u8], sig: &Signature, pubkey: &PublicKey) -> Option<DBValue> {
        let key = UserAddress::from_sig(&msg, &sig, &pubkey);
        self.inner_get(key.as_slice())
    }

    fn write(&self, tx: DBTx) {
        self.inner_write(tx.into_inner())
    }
}

impl KVS for MemoryKVS {
    fn inner_get(&self, key: &[u8]) -> Option<DBValue> {
        let d = self.0.read().unwrap();
        d.get(key).cloned()
    }

    fn inner_write(&self, tx: InnerDBTx) {
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
