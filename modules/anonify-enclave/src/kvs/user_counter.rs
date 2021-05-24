use crate::error::{EnclaveError, Result};
use frame_common::{crypto::AccountId, state_types::UserCounter};
use std::{
    collections::hash_map::HashMap,
    prelude::v1::*,
    sync::{Arc, SgxRwLock},
};

/// A counter that guarantees idempotency and order of messages from users.
/// Verifying that it is incremented by 1 at the time of state transitions.
#[derive(Debug, Clone)]
pub struct UserCounterDB(Arc<SgxRwLock<HashMap<AccountId, UserCounter>>>);

impl UserCounterDB {
    pub fn new() -> Self {
        UserCounterDB(Arc::new(SgxRwLock::new(HashMap::new())))
    }

    pub fn increment(&self, user: AccountId, received: UserCounter) -> Result<()> {
        let mut db = self.0.write().unwrap();
        let curr_counter = db.get(&user).copied().unwrap_or_default();
        if !curr_counter.is_increment(received) {
            return Err(EnclaveError::InvalidUserCounter {
                received,
                expected: curr_counter.increment(),
            });
        }

        db.insert(user, received);
        Ok(())
    }

    pub fn get(&self, account_id: AccountId) -> UserCounter {
        match self.0.read().unwrap().get(&account_id) {
            Some(v) => *v,
            None => UserCounter::default(),
        }
    }
}
