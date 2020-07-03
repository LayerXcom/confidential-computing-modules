use anyhow::Result;
use std::{
    fmt::Debug,
    vec::Vec,
    mem::size_of,
    sync::SgxRwLockWriteGuard,
};
use anonify_common::{
    crypto::{UserAddress, Ciphertext},
    traits::*,
    state_types::{UpdatedState, MemId},
};
use codec::{Encode, Decode};
use anonify_treekem::{
    handshake::{PathSecretRequest, HandshakeParams},
};

/// Execute state transiton functions from runtime
pub trait RuntimeExecutor<G: ContextOps<S>, S: State>: Sized {
    type C: CallKindExecutor<G, S>;

    fn new(db: G) -> Self;
    fn execute(self, kind: Self::C, my_addr: UserAddress) -> Result<Vec<UpdatedState<S>>>;
}

/// Execute state traisiton functions from call kind
pub trait CallKindExecutor<G: ContextOps<S>, S: State>: Sized + Encode + Decode + Debug + Clone {
    type R: RuntimeExecutor<G, S>;

    fn new(id: u32, state: &mut [u8]) -> Result<Self>;
    fn execute(self, runtime: Self::R, my_addr: UserAddress) -> Result<Vec<UpdatedState<S>>>;
}

pub trait ContextOps<S: State>: StateOps<S> + GroupKeyGetter {}

/// A getter of state stored in enclave memory.
pub trait StateOps<S: State> {
    /// Get state using memory id.
    /// Assumed this is called in user-defined state transition functions.
    fn get_state<U>(&self, key: U, mem_id: MemId) -> S
    where
        U: Into<UserAddress>;

    /// Returns a updated state of registerd address in notification.
    fn update_state(
        &self,
        state_iter: impl Iterator<Item=UpdatedState<S>> + Clone
    ) -> Option<UpdatedState<S>>;
}

pub trait GroupKeyGetter {
    type GK: GroupKeyOps;

    fn get_group_key(&self) -> SgxRwLockWriteGuard<Self::GK>;
}

pub trait GroupKeyOps: Sized {
    fn new(
        my_roster_idx: usize,
        max_roster_idx: usize,
        path_secret_req: PathSecretRequest,
    ) -> Result<Self>;

    fn create_handshake(&self) -> Result<HandshakeParams>;

    fn process_handshake(
        &mut self,
        handshake: &HandshakeParams,
    ) -> Result<()>;

    fn encrypt(&self, plaintext: Vec<u8>) -> Result<Ciphertext>;

    fn decrypt(&mut self, app_msg: &Ciphertext) -> Result<Option<Vec<u8>>>;

    /// Ratchet keychain per a transaction
    fn ratchet(&mut self, roster_idx: usize) -> Result<()>;
}
