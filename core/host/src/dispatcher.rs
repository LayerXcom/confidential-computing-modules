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
use crate::components::*;

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    deployer: D,
    sender: Option<S>,
    watcher: Option<W>,
    event_db: Arc<DB>,
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
        let deployer = D::new(enclave_id, node_url)?;

        Ok(Dispatcher {
            deployer,
            event_db,
            sender: None,
            watcher: None,
        })
    }

    pub fn set_contract_addr<P>(&self, contract_addr: &str, abi_path: P) -> Result<()>
        where
            P: AsRef<Path> + Copy,
    {
        let contract_info = ContractInfo::new(abi_path, contract_addr);

        let enclave_id = self.deployer.get_enclave_id();
        let node_url = self.deployer.get_node_url();
        let sender = S::new(enclave_id, node_url, contract_info)?;
        let watcher = W::new(node_url, contract_info, self.event_db.clone())?;

        self.sender = Some(sender);
        self.watcher = Some(watcher);

        Ok(())
    }

    pub fn deploy(
        &self,
        deploy_user: &SignerAddress,
    ) -> Result<String> {
        self.deployer
            .deploy(deploy_user, join_fn)
    }

    pub fn join_group<P: AsRef<Path> + Copy>(
        &self,
        signer: SignerAddress,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String> {
        let contract_info = ContractInfo::new(abi_path, contract_addr);
        self.set_contract_addr(contract_info)?;

        self.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .join_group(signer, gas, join_fn)
    }

    pub fn send_instruction<ST, C>(
        &self,
        access_right: AccessRight,
        state: ST,
        call_name: &str,
        signer: SignerAddress,
        gas: u64,
    ) -> Result<String>
        where
            ST: State,
            C: CallNameConverter,
    {
        if self.sender.is_none() {
            return Err(HostError::AddressNotSet);
        }

        let input = host_input::Instruction<'_, _, C>::new(
            state, call_name. access_right, signer, gas,
        );
        let eid = self.deployer.get_enclave_id();
        let host_output = InstructionWorkflow::exec(input, eid)?;

        self.sender.as_ref().send_instruction(host_output)
    }

    pub fn handshake(
        &self,
        signer: SignerAddress,
        gas: u64,
    ) -> Result<String> {
        if self.sender.is_none() {
            return Err(HostError::AddressNotSet);
        }

        self.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .handshake(signer, gas, handshake_fn)
    }

    pub fn block_on_event<St>(
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

    pub fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.deployer
            .get_account(index)
    }

    pub fn register_notification(&self, access_right: AccessRight) -> Result<()> {
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
