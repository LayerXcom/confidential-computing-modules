use std::{
    sync::SgxRwLock,
    collections::HashMap,
    prelude::v1::*,
};

pub(crate) struct PersistCache {
    cache: SgxRwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl PersistCache {
    pub(crate) fn new() -> Self {
        PersistCache {
            cache: SgxRwLock::new(HashMap::new()),
        }
    }
}

impl rustls::StoresClientSessions for PersistCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.write().unwrap().insert(key, value);
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.read().unwrap().get(key).cloned()
    }
}
