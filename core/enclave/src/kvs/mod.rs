use std::{
    prelude::v1::*,
    collections::HashMap,
    sync::{SgxRwLock, Arc},
};
use ed25519_dalek::{PublicKey, Signature};
use anonify_common::{
    UserAddress,
    kvs::*,
    Hash256, Sha256,
};
use anonify_runtime::{State, MemId, UpdatedState};
use codec::Encode;
use crate::error::Result;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DBKey((UserAddress, MemId));

// TODO: UserAddress+MemId is not sufficient size for hash digest in terms of collision resistance.
impl DBKey {
    pub fn new(addr: UserAddress, mem_id: MemId) -> Self {
        DBKey((addr, mem_id))
    }
}

#[derive(Debug, Clone)]
pub struct EnclaveDB<S: State>(Arc<SgxRwLock<HashMap<DBKey, S>>>);

impl<S: State> EnclaveDB<S> {
    pub fn new() -> Self {
        EnclaveDB(Arc::new(SgxRwLock::new(HashMap::new())))
    }

    pub fn get(&self, address: UserAddress, mem_id: MemId) -> S {
        let key = DBKey::new(address, mem_id);
        match self.0.read().unwrap().get(&key) {
            Some(v) => v.clone(),
            None => S::default(),
        }
    }

    pub fn insert_by_updated_state(&self, updated_state: UpdatedState<S>) {
        let mut tmp = self.0.write().unwrap();
        let key = DBKey::new(updated_state.address, updated_state.mem_id);
        tmp.insert(key, updated_state.state);
    }

    pub fn insert(&self, address: UserAddress, mem_id: MemId, state: S) {
        let mut tmp = self.0.write().unwrap();
        let key = DBKey::new(address, mem_id);
        tmp.insert(key, state);
    }

    pub fn delete(&self, address: UserAddress, mem_id: MemId) {
        let mut tmp = self.0.write().unwrap();
        let key = DBKey::new(address, mem_id);
        tmp.remove(&key);
    }
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
