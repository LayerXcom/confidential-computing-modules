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

#[derive(Debug)]
pub struct EnclaveDB<S: State>(Arc<SgxRwLock<HashMap<UserAddress, StateMap<S>>>>);

/// Trait of key-value store instrctions restricted by signature verifications.
pub trait EnclaveKVS {
    fn new() -> Self;

    fn get(&self, key: &UserAddress, mem_id: &MemId) -> StateValue<S, Current> ;

    fn write(&self, tx: EnclaveDBTx);
}

// impl<S: State> EnclaveKVS for EnclaveDB<S> {

// }

impl<S: State> EnclaveKVS for EnclaveDB<S> {
    fn new() -> Self {
        EnclaveDB(Arc::new(SgxRwLock::new(HashMap::new())))
    }

    fn get(&self, key: &UserAddress, mem_id: &MemId) -> StateValue<S, Current> {
        self.0.read().unwrap()
            .get(key)
            .unwrap_or(StateValue::default())

            .get(mem_id)
            .cloned()
            .unwrap_or(StateValue::default())
        // self.inner_get(key.as_bytes())
        //     .unwrap_or(DBValue::default())
    }

    fn write(&self, tx: EnclaveDBTx) {
        self.inner_write(tx.into_inner())
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
