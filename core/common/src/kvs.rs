use crate::localstd::{
    collections::HashMap,
    vec::Vec,
};
#[cfg(feature = "std")]
use elastic_array::{ElasticArray128, ElasticArray32};
#[cfg(feature = "std")]
use crate::localstd::sync::RwLock;
#[cfg(feature = "sgx")]
use sgx_elastic_array::{ElasticArray128, ElasticArray32};
#[cfg(feature = "sgx")]
use crate::localstd::sync::SgxRwLock as RwLock;

/// Inner trait of key-value store instructions
pub trait KVS: Sync + Send {
    fn tx(&self) -> DBTx { DBTx::new() }

    fn inner_get(&self, key: &[u8]) -> Option<DBValue>;

    fn inner_write(&self, tx: DBTx);
}

/// A key-value database fulfilling the `KVS` trait, living in memory.
#[derive(Debug)]
pub struct MemoryDB(RwLock<HashMap<Vec<u8>, DBValue>>);

impl MemoryDB {
    pub fn new() -> Self {
        MemoryDB(RwLock::new(HashMap::new()))
    }
}

impl KVS for MemoryDB {
    fn inner_get(&self, key: &[u8]) -> Option<DBValue> {
        let d = self.0.read().unwrap();
        d.get(key).cloned()
    }

    fn inner_write(&self, tx: DBTx) {
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

/// Database value.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct DBValue(ElasticArray128<u8>);

impl DBValue {
    pub fn from_slice(slice: &[u8]) -> Self {
        DBValue(ElasticArray128::from_slice(slice))
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

/// Database operation
#[derive(Clone, PartialEq)]
pub enum DBOp {
    Insert {
        key: ElasticArray32<u8>,
        value: DBValue,
    },
    Delete {
        key: ElasticArray32<u8>,
    }
}

impl DBOp {
    /// Returns the key associated with this operation.
    pub fn key(&self) -> &[u8] {
        match *self {
            DBOp::Insert { ref key, .. } => key,
            DBOp::Delete { ref key, .. } => key,
        }
    }
}

/// struct to write transaction. Batches a sequence of put/delete operations for efficiency.
#[derive(Default, Clone, PartialEq)]
pub struct DBTx {
    /// Database operations.
    ops: Vec<DBOp>,
}

impl DBTx {
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    pub fn with_capacity(cap: usize) -> Self {
        DBTx {
            ops: Vec::with_capacity(cap)
        }
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        let mut ekey = ElasticArray32::new();
        ekey.append_slice(key);
        self.ops.push(DBOp::Insert {
            key: ekey,
            value: DBValue::from_slice(value),
        });
    }

    pub fn delete(&mut self, key: &[u8]) {
        let mut ekey = ElasticArray32::new();
        ekey.append_slice(key);
        self.ops.push(DBOp::Delete {
            key: ekey,
        });
    }
}
