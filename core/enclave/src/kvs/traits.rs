use std::prelude::v1::*;
use super::*;
use crate::error::Result;

pub trait KVS: Sync + Send {
    fn tx(&self) -> DBTx { DBTx::new() }

    fn get(&self, key: &[u8]) -> Option<DBValue>;

    fn write(&self, tx: DBTx);
}
