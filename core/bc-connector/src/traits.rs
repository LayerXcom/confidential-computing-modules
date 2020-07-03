#![allow(dead_code)]

use std::{
    path::Path,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use anonify_types::{RawJoinGroupTx, RawInstructionTx, RawHandshakeTx};
use anonify_common::{
    traits::*,
    crypto::AccessRight,
    state_types::UpdatedState,
};
use crate::{
    error::Result,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    utils::*,
};

/// A trait for deploying contracts
pub trait Deployer: Sized {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self>;

    fn get_account(&self, index: usize) -> Result<SignerAddress>;

    /// Deploying contract with attestation.
    fn deploy<F>(
        &mut self,
        deploy_user: &SignerAddress,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawJoinGroupTx>;

    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind>;

    fn get_enclave_id(&self) -> sgx_enclave_id_t;

    fn get_node_url(&self) -> &str;

    fn register_notification<F>(
        &self,
        access_right: AccessRight,
        reg_notify_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(sgx_enclave_id_t, AccessRight) -> Result<()>;
}

/// A trait for sending transactions to blockchain nodes
pub trait Sender: Sized {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<Self>;

    fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: ContractKind,
    ) -> Self;

    fn get_account(&self, index: usize) -> Result<SignerAddress>;

    /// Send an encrypted instruction of state transition to blockchain nodes.
    fn send_instruction<ST, F, C>(
        &self,
        access_right: AccessRight,
        signer: SignerAddress,
        state_info: StateInfo<'_, ST, C>,
        gas: u64,
        st_fn: F,
        ciphertext_len: usize,
    ) -> Result<String>
    where
        ST: State,
        C: CallNameConverter,
        F: FnOnce(sgx_enclave_id_t, AccessRight, StateInfo<'_, ST, C>) -> Result<RawInstructionTx>;

    /// Attestation with deployed contract.
    fn join_group<F>(
        &self,
        signer: SignerAddress,
        gas: u64,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawJoinGroupTx>;

    fn handshake<F>(
        &self,
        signer: SignerAddress,
        gas: u64,
        handshake_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawHandshakeTx>;

    fn get_contract(self) -> ContractKind;
}

/// A trait of fetching event from blockchian nodes
pub trait Watcher: Sized {
    type WatcherDB: BlockNumDB;

    fn new<P: AsRef<Path>>(
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
        event_db: Arc<Self::WatcherDB>,
    ) -> Result<Self>;

    /// Blocking event fetch from blockchain nodes.
    fn block_on_event<F, S>(
        &self,
        eid: sgx_enclave_id_t,
        insert_fn: F,
    ) -> Result<Option<Vec<UpdatedState<S>>>>
    where
        F: FnOnce(sgx_enclave_id_t, &InnerEnclaveLog, usize) -> Result<Option<Vec<UpdatedState<S>>>>,
        S: State
    ;

    fn get_contract(self) -> ContractKind;
}
