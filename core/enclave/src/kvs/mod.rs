use std::{
    prelude::v1::*,
    collections::HashMap,
    sync::{SgxRwLock, Arc},
};
use ed25519_dalek::{PublicKey, Signature};
use anonify_common::{
    UserAddress,
    kvs::*,
};
use anonify_stf::State;
use crate::state::{StateValue, Current};
use crate::error::Result;

#[derive(Debug)]
struct StateMap<S: State>(HashMap<MemId, StateValue<S, Current>>);

#[derive(Debug, Clone)]
pub struct EnclaveDB<S: State>(Arc<SgxRwLock<HashMap<UserAddress, StateMap<S>>>>);

/// Trait of key-value store instrctions restricted by signature verifications.
pub trait EnclaveKVS {
    fn new() -> Self;

    fn get<S: State>(&self, address: &UserAddress, mem_id: &MemId) -> StateValue<S, Current>;

    fn write<S: State>(&self, address: UserAddress, mem_id: MemId, sv: StateValue<S, Current>);
}

// impl<S: State> EnclaveKVS for EnclaveDB<S> {

// }

impl<S: State> EnclaveDB<S> {
    pub fn new() -> Self {
        EnclaveDB(Arc::new(SgxRwLock::new(HashMap::new())))
    }

    pub fn get(&self, address: &UserAddress, mem_id: &MemId) -> StateValue<S, Current> {
        match self.0.read().unwrap().get(address) {
            Some(v) => {
                v.0.get(mem_id)
                .cloned()
                .unwrap_or(StateValue::default())
            },
            None => return StateValue::default()
        }
    }

    pub fn write(&self, address: UserAddress, mem_id: MemId, sv: StateValue<S, Current>) {
        let tmp = self.0.write().unwrap();
        match tmp.get_mut(&address) {
            Some(c) => {
                c.0.insert(mem_id, sv);
            },
            None => {
                let mut c = HashMap::new();
                c.insert(mem_id, sv);
                tmp.insert(address, StateMap(c));
            }
        }
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
