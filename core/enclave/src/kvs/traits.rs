use std::prelude::v1::*;
use super::*;
use crate::{
    error::Result,
};

/// Inner trait of key-value store instructions
pub trait KVS: Sync + Send {
    fn tx(&self) -> DBTx { DBTx::new() }

    fn get(&self, key: &[u8]) -> Option<DBValue>;

    fn write(&self, tx: DBTx);
}

/// Trait of key-value store instrctions restricted by signature verifications.
pub trait SigVerificationKVS: Sync + Send {
    type KVS: KVS;

    fn get(&self, msg: &[u8], sig: [u8; 64]) -> Option<DBValue>;

    fn write(&self, tx: DBTx);
}
