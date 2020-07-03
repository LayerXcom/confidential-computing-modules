use crate::local_anyhow::{Result, anyhow};
use crate::localstd::{
    fmt::Debug,
    vec::Vec,
    mem::size_of,
};
use crate::state_type::StateType;
use anonify_common::{UserAddress, Ciphertext, traits::*};
use codec::{Encode, Decode};
use anonify_treekem::{
    GroupState, AppKeyChain, Handshake,
    handshake::{PathSecretRequest, HandshakeParams},
};

/// A getter of state stored in enclave memory.
pub trait StateGetter<S: State> {
    /// Get state using memory id.
    /// Assumed this is called in user-defined state transition functions.
    fn get_trait<U>(&self, key: U, mem_id: MemId) -> S
    where
        U: Into<UserAddress>;

    fn get_type(&self, key: UserAddress, mem_id: MemId) -> S;
}

/// Execute state transiton functions from runtime
pub trait RuntimeExecutor<G: StateGetter<S>, S: State>: Sized {
    type C: CallKindExecutor<G, S>;

    fn new(db: G) -> Self;
    fn execute(self, kind: Self::C, my_addr: UserAddress) -> Result<Vec<UpdatedState<S>>>;
}

/// Execute state traisiton functions from call kind
pub trait CallKindExecutor<G: StateGetter<S>, S: State>: Sized + Encode + Decode + Debug + Clone {
    type R: RuntimeExecutor<G, S>;

    fn new(id: u32, state: &mut [u8]) -> Result<Self>;
    fn execute(self, runtime: Self::R, my_addr: UserAddress) -> Result<Vec<UpdatedState<S>>>;
}

pub trait ContextOps<S: State> {
    fn get_group_key<GK: GroupKeyOps>(&self) -> GroupKeyOps;

    fn update_state(
        &self,
        state_iter: impl Iterator<Item=UpdatedState<S>> + Clone
    ) -> Option<UpdatedState<S>>;
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
}
