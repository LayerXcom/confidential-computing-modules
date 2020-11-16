use frame_common::{
    crypto::AccountId,
    state_types::{MemId, StateType, UpdatedState},
};
use std::{
    collections::hash_map::HashMap,
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

    pub fn values(&self) -> Vec<StateType> {
        let mut acc = vec![];
        for v in self.0.read().unwrap().values() {
            acc.push(v.clone());
        }
        acc
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
