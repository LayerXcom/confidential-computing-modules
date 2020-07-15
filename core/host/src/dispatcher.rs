use std::{
    path::Path,
    sync::Arc,
    convert::{TryInto, TryFrom},
    fmt::Debug,
};
use anonify_bc_connector::{
    traits::*,
    utils::*,
    eventdb::BlockNumDB,
    error::{Result, HostError},
};
use anonify_common::{
    crypto::AccessRight,
    traits::{State, MemNameConverter, CallNameConverter},
    state_types::UpdatedState,
};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use crate::bridges::ecalls::{
    join_group as join_fn,
    encrypt_instruction as enc_ins_fn,
    handshake as handshake_fn,
    insert_logs as insert_fn,
    register_notification as reg_notify_fn,
    get_state_from_enclave,
};

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    inner: RwLock<SgxDispatcher<D, S, W, DB>>,
}

impl<D, S, W, DB> Dispatcher<D, S, W, DB>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    pub fn new(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let inner = SgxDispatcher::new_with_deployer(enclave_id, node_url, event_db)?;

        Ok(Dispatcher {
            inner: RwLock::new(inner)
        })
    }

    pub fn set_contract_addr<P>(&self, contract_addr: &str, abi_path: P) -> Result<()>
        where
            P: AsRef<Path> + Copy,
    {
        let mut inner = self.inner.write();
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        inner.set_contract_addr(contract_info)?;

        Ok(())
    }

    pub fn deploy(
        &self,
        deploy_user: &SignerAddress,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        inner.deploy(deploy_user)
    }

    pub fn join_group<P: AsRef<Path> + Copy>(
        &self,
        signer: SignerAddress,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        inner.join_group(signer, gas, contract_info)
    }

    pub fn send_instruction<ST, C>(
        &self,
        access_right: AccessRight,
        state: ST,
        call_name: &str,
        signer: SignerAddress,
        gas: u64,
        ciphertext_len: usize,
    ) -> Result<String>
        where
            ST: State,
            C: CallNameConverter,
    {
        let state_info = StateInfo::<_, C>::new(state, call_name);
        self.inner
            .read()
            .send_instruction(access_right, signer, state_info, gas, ciphertext_len)
    }

    pub fn handshake(
        &self,
        signer: SignerAddress,
        gas: u64,
    ) -> Result<String> {
        self.inner
            .read()
            .handshake(signer, gas)
    }

    pub fn block_on_event<St>(
        &self,
    ) -> Result<Option<Vec<UpdatedState<St>>>>
        where
            St: State,
    {
        self.inner
            .read()
            .block_on_event()
            .into()
    }

    pub fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.inner
            .read()
            .get_account(index)
    }

    pub fn register_notification(&self, access_right: AccessRight) -> Result<()> {
        self.inner
            .read()
            .register_notification(access_right)
    }
}

#[derive(Debug)]
struct SgxDispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    deployer: D,
    sender: Option<S>,
    watcher: Option<W>,
    event_db: Arc<DB>,
}

impl<D, S, W, DB> SgxDispatcher<D, S, W, DB>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    fn new_with_deployer(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let deployer = D::new(enclave_id, node_url)?;

        Ok(SgxDispatcher {
            deployer,
            event_db,
            sender: None,
            watcher: None,
        })
    }

    fn set_contract_addr<P>(
        &mut self,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<()>
        where
            P: AsRef<Path> + Copy
    {
        let enclave_id = self.deployer.get_enclave_id();
        let node_url = self.deployer.get_node_url();
        let sender = S::new(enclave_id, node_url, contract_info)?;
        let watcher = W::new(node_url, contract_info, self.event_db.clone())?;

        self.sender = Some(sender);
        self.watcher = Some(watcher);

        Ok(())
    }

    fn deploy(
        &mut self,
        deploy_user: &SignerAddress,
    ) -> Result<String> {
        self.deployer
            .deploy(deploy_user, join_fn)
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.deployer
            .get_account(index)
    }

    fn block_on_event<St>(
        &self,
    ) -> Result<Option<Vec<UpdatedState<St>>>>
        where
            St: State,
    {
        if self.watcher.is_none() {
            return Err(HostError::EventWatcherNotSet);
        }

        let eid = self.deployer.get_enclave_id();
        self.watcher
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .block_on_event(eid, insert_fn)
    }

    fn join_group<P: AsRef<Path> + Copy>(
        &mut self,
        signer: SignerAddress,
        gas: u64,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<String> {
        self.set_contract_addr(contract_info)?;

        self.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .join_group(signer, gas, join_fn)
    }

    fn send_instruction<ST, C>(
        &self,
        access_right: AccessRight,
        signer: SignerAddress,
        state_info: StateInfo<'_, ST, C>,
        gas: u64,
        ciphertext_len: usize,
    ) -> Result<String>
        where
            ST: State,
            C: CallNameConverter,
    {
        if self.sender.is_none() {
            return Err(HostError::AddressNotSet);
        }

        self.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .send_instruction(access_right, signer, state_info, gas, enc_ins_fn, ciphertext_len)
    }

    fn handshake(
        &self,
        signer: SignerAddress,
        gas: u64,
    ) -> Result<String>
    {
        if self.sender.is_none() {
            return Err(HostError::AddressNotSet);
        }

        self.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .handshake(signer, gas, handshake_fn)
    }

    fn register_notification(&self, access_right: AccessRight) -> Result<()> {
        self.deployer.register_notification(access_right, reg_notify_fn)
    }
}

pub fn get_state<S, M>(
    access_right: AccessRight,
    enclave_id: sgx_enclave_id_t,
    mem_name: &str,
) -> Result<S>
    where
        S: State + TryFrom<Vec<u8>>,
        <S as TryFrom<Vec<u8>>>::Error: Debug,
        M: MemNameConverter,
{
    let state = get_state_from_enclave::<M>(
        enclave_id,
        access_right,
        mem_name,
    )?
        .try_into()
        .expect("Failed to convert into State trait.");

    Ok(state)
}
