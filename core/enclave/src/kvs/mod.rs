use std::prelude::v1::*;
use elastic_array::{ElasticArray128, ElasticArray32};
use ed25519_dalek::{PublicKey, Signature};
use anonify_common::UserAddress;
use crate::{
    error::Result,
};

mod memorydb;
pub mod traits;

pub use memorydb::{MemoryKVS, MEMORY_DB};
pub use traits::SigVerificationKVS;

/// Database value.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct DBValue(ElasticArray128<u8>);

impl DBValue {
    pub fn from_slice(slice: &[u8]) -> Self {
        DBValue(ElasticArray128::from_slice(slice))
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.into_vec()
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

/// Batches a sequence of put/delete operations for efficiency.
/// These operations are protected from signature verifications.
#[derive(Default, Clone, PartialEq)]
pub struct DBTx(InnerDBTx);

impl DBTx {
    pub fn new() -> Self {
        DBTx(InnerDBTx::new())
    }

    /// Put instruction is added to a transaction only if the verification of provided signature returns true.
    pub fn put(
        &mut self,
        user_address: &UserAddress,
        msg: &[u8],
    ) {
        self.0.put(user_address.as_bytes(), msg);
    }

    /// Delete instruction is added to a transaction only if the verification of provided signature returns true.
    pub fn delete(
        &mut self,
        msg: &[u8],
        sig: &Signature,
        pubkey: &PublicKey,
    ) {
        let key = UserAddress::from_sig(&msg, &sig, &pubkey);
        self.0.delete(key.as_bytes());
    }

    pub(crate) fn into_inner(self) -> InnerDBTx {
        self.0
    }
}

/// Inner struct to write transaction. Batches a sequence of put/delete operations for efficiency.
#[derive(Default, Clone, PartialEq)]
pub(crate) struct InnerDBTx {
    /// Database operations.
    ops: Vec<DBOp>,
}

impl InnerDBTx {
    fn new() -> Self {
        Self::with_capacity(256)
    }

    fn with_capacity(cap: usize) -> Self {
        InnerDBTx {
            ops: Vec::with_capacity(cap)
        }
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

