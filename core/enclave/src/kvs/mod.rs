use std::prelude::v1::*;
use elastic_array::{ElasticArray128, ElasticArray32};
use crate::{
    error::Result,
};

mod memorydb;
mod traits;

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

    pub fn put_by_sig(&mut self, msg: &[u8], sig: [u8; 64], value: &[u8]) -> Result<()> {


        Ok(())
    }

    pub fn delete_by_sig(&mut self, msg: &[u8], sig: [u8; 64]) {

    }

    fn put(&mut self, key: &[u8], value: &[u8]) {
        let mut ekey = ElasticArray32::new();
        ekey.append_slice(key);
        self.ops.push(DBOp::Insert {
            key: ekey,
            value: DBValue::from_slice(value),
        });
    }

    fn delete(&mut self, key: &[u8]) {
        let mut ekey = ElasticArray32::new();
        ekey.append_slice(key);
        self.ops.push(DBOp::Delete {
            key: ekey,
        });
    }
}
