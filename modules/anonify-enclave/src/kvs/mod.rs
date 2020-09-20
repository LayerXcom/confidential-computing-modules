use crate::error::Result;
use ed25519_dalek::{PublicKey, Signature};
use frame_common::{
    crypto::AccountId,
    kvs::*,
    state_types::{MemId, StateType, UpdatedState},
};
use std::{
    collections::HashMap,
    prelude::v1::*,
    sync::{Arc, SgxRwLock},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DBKey((AccountId, MemId));

// TODO: AccountId+MemId is not sufficient size for hash digest in terms of collision resistance.
impl DBKey {
    pub fn new(account_id: AccountId, mem_id: MemId) -> Self {
        DBKey((account_id, mem_id))
    }
}

#[derive(Debug, Clone)]
pub struct EnclaveDB(Arc<SgxRwLock<HashMap<DBKey, StateType>>>);

impl EnclaveDB {
    pub fn new() -> Self {
        EnclaveDB(Arc::new(SgxRwLock::new(HashMap::new())))
    }

    pub fn get(&self, account_id: AccountId, mem_id: MemId) -> StateType {
        let key = DBKey::new(account_id, mem_id);
        match self.0.read().unwrap().get(&key) {
            Some(v) => v.clone(),
            None => StateType::default(),
        }
    }

    pub fn insert_by_updated_state(&self, updated_state: UpdatedState<StateType>) {
        let mut tmp = self.0.write().unwrap();
        let key = DBKey::new(updated_state.account_id, updated_state.mem_id);
        tmp.insert(key, updated_state.state);
    }

    pub fn insert(&self, account_id: AccountId, mem_id: MemId, state: StateType) {
        let mut tmp = self.0.write().unwrap();
        let key = DBKey::new(account_id, mem_id);
        tmp.insert(key, state);
    }

    pub fn delete(&self, account_id: AccountId, mem_id: MemId) {
        let mut tmp = self.0.write().unwrap();
        let key = DBKey::new(account_id, mem_id);
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
    pub fn put(&mut self, account_id: &AccountId, msg: &[u8]) {
        self.0.put(account_id.as_bytes(), msg);
    }

    /// Delete instruction is added to a transaction only if the verification of provided signature returns true.
    pub fn delete(&mut self, msg: &[u8], sig: &Signature, pubkey: &PublicKey) -> Result<()> {
        let key = AccountId::from_sig(&msg, &sig, &pubkey)?;
        self.0.delete(key.as_bytes());

        Ok(())
    }

    pub(crate) fn into_inner(self) -> DBTx {
        self.0
    }
}
