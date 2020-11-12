use crate::local_anyhow::Result;
use crate::localstd::{
    fmt::Debug,
    string::String,
    sync::{SgxRwLockReadGuard, SgxRwLockWriteGuard},
    vec::Vec,
};
use codec::{Decode, Encode};
use frame_common::{
    crypto::{AccountId, Ciphertext, ExportHandshake, ExportPathSecret},
    state_types::{MemId, ReturnState, UpdatedState},
    traits::*,
};
use frame_treekem::{handshake::HandshakeParams, DhPubKey, EciesCiphertext};

/// Execute state transition functions from runtime
pub trait RuntimeExecutor<G: ContextOps>: Sized {
    type C: CallKindExecutor<G>;
    type S: State;

    fn new(db: G) -> Self;
    fn execute(self, kind: Self::C, my_account_id: AccountId) -> Result<ReturnState<Self::S>>;
}

/// Execute state transition functions from call kind
pub trait CallKindExecutor<G: ContextOps>: Sized + Encode + Decode + Debug + Clone {
    type R: RuntimeExecutor<G>;
    type S: State;

    fn new(id: u32, state: &mut [u8]) -> Result<Self>;
    fn execute(self, runtime: Self::R, my_account_id: AccountId) -> Result<ReturnState<Self::S>>;
}

pub trait ContextOps:
    StateOps + GroupKeyGetter + NotificationOps + IdentityKeyOps + QuoteGetter
{
    fn mrenclave_ver(&self) -> usize;
}

/// A getter of state stored in enclave memory.
pub trait StateOps {
    type S: State;

    /// Get state using memory id.
    /// Assumed this is called in user-defined state transition functions.
    fn get_state_by_mem_id<U>(&self, key: U, mem_id: MemId) -> Self::S
    where
        U: Into<AccountId>;

    /// Get state using call id.
    /// this is called in user-defined state getting functions.
    fn get_state_by_call_id<U, R, CTX>(ctx: CTX, call_id: u32, account_id: U) -> Result<Self::S>
    where
        U: Into<AccountId>,
        R: RuntimeExecutor<CTX, S = Self::S>,
        CTX: ContextOps<S = Self::S>;

    /// Returns a updated state of registered account_id in notification.
    fn update_state(
        &self,
        state_iter: impl Iterator<Item = UpdatedState<Self::S>> + Clone,
    ) -> Option<UpdatedState<Self::S>>;
}

pub trait GroupKeyGetter {
    type GK: GroupKeyOps;

    fn read_group_key(&self) -> SgxRwLockReadGuard<Self::GK>;

    fn write_group_key(&self) -> SgxRwLockWriteGuard<Self::GK>;
}

pub trait NotificationOps {
    fn set_notification(&self, account_id: AccountId) -> bool;

    fn is_notified(&self, account_id: &AccountId) -> bool;
}

pub trait IdentityKeyOps {
    fn sign(&self, msg: &[u8]) -> Result<secp256k1::Signature>;

    fn decrypt(&self, ciphertext: EciesCiphertext) -> Result<Vec<u8>>;

    fn encrypting_key(&self) -> DhPubKey;
}

pub trait GroupKeyOps: Sized {
    fn create_handshake(&self) -> Result<(ExportHandshake, ExportPathSecret)>;

    fn process_handshake(&mut self, handshake: &HandshakeParams) -> Result<()>;

    fn encrypt(&self, plaintext: Vec<u8>) -> Result<Ciphertext>;

    fn decrypt(&self, app_msg: &Ciphertext) -> Result<Option<Vec<u8>>>;

    /// Ratchet sender's keychain per a transaction
    fn sender_ratchet(&mut self, roster_idx: usize) -> Result<()>;

    /// Ratchet receiver's keychain per a transaction
    fn receiver_ratchet(&mut self, roster_idx: usize) -> Result<()>;

    /// Syncing the sender and receiver app keychains
    fn sync_ratchet(&mut self, roster_idx: usize, msg_gen: u32) -> Result<()>;

    fn my_roster_idx(&self) -> u32;
}

pub trait QuoteGetter: Sized {
    /// Generate Base64-encoded QUOTE data structure.
    /// QUOTE will be sent to Attestation Service to verify SGX's status.
    /// For more information: https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
    fn quote(&self) -> Result<String>;
}
