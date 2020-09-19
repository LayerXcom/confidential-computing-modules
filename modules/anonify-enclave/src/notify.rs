use std::{
    collections::HashSet,
    sync::{SgxRwLock, Arc},
};
use frame_common::crypto::AccountId;

#[derive(Debug, Clone)]
pub struct Notifier {
    account_ids: Arc<SgxRwLock<HashSet<AccountId>>>,
}

impl Notifier {
    pub fn new() -> Self {
        let account_ids = HashSet::new();
        Notifier {
            account_ids: Arc::new(SgxRwLock::new(account_ids)),
        }
    }

    pub fn register(&self, account_id: AccountId) -> bool {
        let mut tmp = self.account_ids.write().unwrap();
        tmp.insert(account_id)
    }

    pub fn contains(&self, account_id: &AccountId) -> bool {
        self.account_ids.read().unwrap().contains(&account_id)
    }
}
