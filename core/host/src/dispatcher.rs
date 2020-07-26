use std::{
    path::Path,
    sync::Arc,
    convert::{TryInto, TryFrom},
    fmt::Debug,
};
use crate::{
    traits::*,
    utils::*,
    eventdb::BlockNumDB,
    error::{Result, HostError},
};
use frame_common::{
    crypto::AccessRight,
    traits::*,
    state_types::{UpdatedState, StateType},
};
use frame_host::engine::HostEngine;
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use web3::types::Address;
use crate::ecalls::{
    insert_logs as insert_fn,
};
use crate::workflow::*;

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    inner: RwLock<InnerDispatcher<D, S, W, DB>>,
}

#[derive(Debug)]
struct InnerDispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
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
        let inner = RwLock::new(
            InnerDispatcher {
                deployer,
                event_db,
                sender: None,
                watcher: None,
            }
        );

        Ok(Dispatcher { inner })
    }

    pub fn set_contract_addr<P: AsRef<Path> + Copy>(
        &self,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<()> {
        let mut inner = self.inner.write();
        let enclave_id = inner.deployer.get_enclave_id();
        let node_url = inner.deployer.get_node_url();

        let contract_info = ContractInfo::new(abi_path, contract_addr);
        let sender = S::new(enclave_id, node_url, contract_info)?;
        let watcher = W::new(node_url, contract_info, inner.event_db.clone())?;

        inner.sender = Some(sender);
        inner.watcher = Some(watcher);

        Ok(())
    }

    pub fn deploy(
        &self,
        deploy_user: Address,
        gas: u64,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::JoinGroup::new(deploy_user, gas);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        inner.deployer
            .deploy(host_output)
    }

    pub fn join_group<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<String> {
        self.set_contract_addr(contract_addr, abi_path)?;

        let inner = self.inner.read();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::JoinGroup::new(signer, gas);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        inner.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .join_group(host_output)
    }

    pub fn send_instruction<ST, C>(
        &self,
        access_right: AccessRight,
        state: ST,
        call_name: &str,
        signer: Address,
        gas: u64,
    ) -> Result<String>
        where
            ST: State,
            C: CallNameConverter,
    {
        let inner = self.inner.read();
        let input = host_input::Instruction::<ST, C>::new(
            state, call_name.to_string(), access_right, signer, gas,
        );
        let eid = inner.deployer.get_enclave_id();
        let host_output = InstructionWorkflow::exec(input, eid)?;

        match &inner.sender {
            Some(s) => s.send_instruction(host_output),
            None => Err(HostError::AddressNotSet),
        }
    }

    pub fn handshake(
        &self,
        signer: Address,
        gas: u64,
    ) -> Result<String> {
        let inner = self.inner.read();
        let input = host_input::Handshake::new(signer, gas);
        let eid = inner.deployer.get_enclave_id();
        let host_output = HandshakeWorkflow::exec(input, eid)?;

        inner.sender.as_ref()
            .ok_or(HostError::AddressNotSet)?
            .handshake(host_output)
    }

    pub fn block_on_event<St>(
        &self,
    ) -> Result<Option<Vec<UpdatedState<St>>>>
        where
            St: State,
    {
        let inner = self.inner.read();
        

        let eid = inner.deployer.get_enclave_id();
        inner.watcher
            .as_ref()
            .ok_or(HostError::EventWatcherNotSet)?
            .block_on_event(eid, insert_fn)
    }

    pub fn get_account(&self, index: usize) -> Result<Address> {
        self.inner
            .read()
            .deployer
            .get_account(index)
    }

    pub fn register_notification(&self, access_right: AccessRight) -> Result<()> {
        let inner = self.inner.read();
        let input = host_input::RegisterNotification::new(access_right);
        let eid = inner.deployer.get_enclave_id();
        let host_output = RegisterNotificationWorkflow::exec(input, eid)?;

        Ok(())
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
    let mem_id = M::as_id(mem_name);
    let input = host_input::GetState::new(access_right, mem_id);
    let mut host_output = GetStateWorkflow::exec(input, enclave_id)
        .ecall_output.unwrap();
    let state = S::decode_s(host_output.as_mut_bytes())

    Ok(state)
}
