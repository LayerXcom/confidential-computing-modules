use std::prelude::v1::*;
use super::*;
use anonify_common::UserAddress;
use crate::{
    error::Result,
};
use ed25519_dalek::{PublicKey, Signature};

/// Inner trait of key-value store instructions
pub(super) trait KVS: Sync + Send {
    fn tx(&self) -> DBTx { DBTx::new() }

    fn inner_get(&self, key: &[u8]) -> Option<DBValue>;

    fn inner_write(&self, tx: InnerDBTx);
}

/// Trait of key-value store instrctions restricted by signature verifications.
pub trait SigVerificationKVS: Sync + Send {
    fn get(&self, key: &UserAddress) -> Option<DBValue>;

    fn write(&self, tx: DBTx);
}
