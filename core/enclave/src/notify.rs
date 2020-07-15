use std::{
    collections::HashSet,
    sync::{SgxRwLock, Arc},
};
use anonify_common::{
    crypto::UserAddress,
    traits::State,
    state_types::{UpdatedState, StateType},
};
use crate::{
    error::Result,
};

#[derive(Debug, Clone)]
pub struct Notifier {
    addresses: Arc<SgxRwLock<HashSet<UserAddress>>>,
}

impl Notifier {
    pub fn new() -> Self {
        let addresses = HashSet::new();
        Notifier {
            addresses: Arc::new(SgxRwLock::new(addresses)),
        }
    }

    pub fn register(&self, address: UserAddress) -> bool {
        let mut tmp = self.addresses.write().unwrap();
        tmp.insert(address)
    }

    pub fn contains(&self, address: &UserAddress) -> bool {
        self.addresses.read().unwrap().contains(&address)
    }
}
