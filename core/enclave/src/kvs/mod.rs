use std::{
    prelude::v1::*,
};
use ed25519_dalek::{PublicKey, Signature};
use anonify_common::{
    UserAddress,
    kvs::*,
};
use crate::error::Result;

/// Trait of key-value store instrctions restricted by signature verifications.
pub trait EnclaveDB: Sync + Send {
    fn new() -> Self;

    fn get(&self, key: &UserAddress) -> DBValue;

    fn write(&self, tx: EnclaveDBTx);
}

impl EnclaveDB for MemoryDB {
    fn new() -> Self {
        MemoryDB::new()
    }

    fn get(&self, key: &UserAddress) -> DBValue {
        self.inner_get(key.as_bytes()).unwrap_or(DBValue::default())
    }

    fn write(&self, tx: EnclaveDBTx) {
        self.inner_write(tx.into_inner())
    }

    // fn state_hash(&self) -> StateHash {

    // }
}

/// Batches a sequence of put/delete operations for efficiency.
/// These operations are protected from signature verifications.
#[derive(Default, Clone, PartialEq)]
pub struct EnclaveDBTx(DBTx);

impl EnclaveDBTx {
    pub fn new() -> Self {
        EnclaveDBTx(DBTx::new())
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
    ) -> Result<()> {
        let key = UserAddress::from_sig(&msg, &sig, &pubkey)?;
        self.0.delete(key.as_bytes());

        Ok(())
    }

    pub(crate) fn into_inner(self) -> DBTx {
        self.0
    }
}
