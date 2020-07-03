use std::{
    collections::HashSet,
    sync::{SgxRwLock, Arc},
};
use anonify_common::{
    crypto::UserAddress,
    traits::State,
    state_types::UpdatedState,
};
use anonify_types::RawUpdatedState;
use crate::{
    error::Result,
    bridges::ocalls::save_to_host_memory,
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

pub fn updated_state_into_raw<S: State>(updated_state: UpdatedState<S>) -> Result<RawUpdatedState> {
    let state = save_to_host_memory(&updated_state.state.as_bytes())? as *const u8;

    Ok(RawUpdatedState {
        address: updated_state.address.into_array(),
        mem_id: updated_state.mem_id.as_raw(),
        state,
    })
}
