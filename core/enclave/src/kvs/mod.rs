mod memorydb;
mod traits;

use elastic_array::{ElasticArray128, ElasticArray32};
use std::prelude::v1::*;

/// Database value.
pub type DBValue = ElasticArray128<u8>;

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

/// Write transaction. Batches a sequence of put/delete operations for efficiency.
#[derive(Default, Clone, PartialEq)]
pub struct DBTransaction {
    /// Database operations.
    ops: Vec<DBOp>,
}

impl DBTransaction {
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    pub fn with_capacity(cap: usize) -> Self {
        DBTransaction {
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
