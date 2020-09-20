use crate::workflow::*;
use crate::{
    error::{HostError, Result},
    eventdb::BlockNumDB,
    traits::*,
    utils::*,
    workflow::host_input,
};
use frame_common::{crypto::ExportPathSecret, state_types::UpdatedState, traits::*};
use frame_host::engine::HostEngine;
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    path::Path,
    sync::Arc,
};
use web3::types::{Address, TransactionReceipt};

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB = DB>, DB: BlockNumDB> {
    inner: RwLock<InnerDispatcher<D, S, W, DB>>,
}

#[derive(Debug)]
struct InnerDispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB = DB>, DB: BlockNumDB> {
    deployer: D,
    sender: Option<S>,
    watcher: Option<W>,
    event_db: Arc<DB>,
}

impl<D, S, W, DB> Dispatcher<D, S, W, DB>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB = DB>,
    DB: BlockNumDB,
{
    pub fn new(enclave_id: sgx_enclave_id_t, node_url: &str, event_db: Arc<DB>) -> Result<Self> {
        let deployer = D::new(enclave_id, node_url)?;
        let inner = RwLock::new(InnerDispatcher {
            deployer,
            event_db,
            sender: None,
            watcher: None,
        });

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

    pub fn deploy<P: AsRef<Path>>(
        &self,
        deploy_user: Address,
        gas: u64,
        confirmations: usize,
        abi_path: P,
        bin_path: P,
    ) -> Result<(String, ExportPathSecret)> {
        let mut inner = self.inner.write();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::JoinGroup::new(deploy_user, gas);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        let contract_addr =
            inner
                .deployer
                .deploy(host_output.clone(), confirmations, abi_path, bin_path)?;
        let export_path_secret = host_output
            .ecall_output
            .expect("must have ecall_output")
            .export_path_secret();

        Ok((contract_addr, export_path_secret))
    }

    pub fn join_group<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
        confirmations: usize,
    ) -> Result<(TransactionReceipt, ExportPathSecret)> {
        self.set_contract_addr(contract_addr, abi_path)?;

        let inner = self.inner.read();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::JoinGroup::new(signer, gas);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        let receipt = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .join_group(host_output.clone(), confirmations)?;

        let export_path_secret = host_output
            .ecall_output
            .expect("must have ecall_output")
            .export_path_secret();

        Ok((receipt, export_path_secret))
    }

    pub fn send_instruction<ST, C, AP>(
        &self,
        access_policy: AP,
        state: ST,
        call_name: &str,
        signer: Address,
        gas: u64,
        confirmations: usize,
    ) -> Result<TransactionReceipt>
    where
        ST: State,
        C: CallNameConverter,
        AP: AccessPolicy,
    {
        let inner = self.inner.read();
        let input = host_input::Instruction::<ST, C, AP>::new(
            state,
            call_name.to_string(),
            access_policy,
            signer,
            gas,
        );
        let eid = inner.deployer.get_enclave_id();
        let host_output = InstructionWorkflow::exec(input, eid)?;

        match &inner.sender {
            Some(s) => s.send_instruction(host_output, confirmations),
            None => Err(HostError::AddressNotSet),
        }
    }

    pub fn handshake(
        &self,
        signer: Address,
        gas: u64,
        confirmations: usize,
    ) -> Result<(TransactionReceipt, ExportPathSecret)> {
        let inner = self.inner.read();
        let input = host_input::Handshake::new(signer, gas);
        let eid = inner.deployer.get_enclave_id();
        let host_output = HandshakeWorkflow::exec(input, eid)?;

        let receipt = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .handshake(host_output.clone(), confirmations)?;
        let export_path_secret = host_output
            .ecall_output
            .expect("must have ecall_output")
            .export_path_secret();

        Ok((receipt, export_path_secret))
    }

    pub fn block_on_event<St>(&self) -> Result<Option<Vec<UpdatedState<St>>>>
    where
        St: State,
    {
        let inner = self.inner.read();

        let eid = inner.deployer.get_enclave_id();
        inner
            .watcher
            .as_ref()
            .ok_or(HostError::EventWatcherNotSet)?
            .block_on_event(eid)
    }

    pub fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.inner.read().deployer.get_account(index, password)
    }

    pub fn register_notification<AP>(&self, access_policy: AP) -> Result<()>
    where
        AP: AccessPolicy,
    {
        let inner = self.inner.read();
        let input = host_input::RegisterNotification::new(access_policy);
        let eid = inner.deployer.get_enclave_id();
        let _host_output = RegisterNotificationWorkflow::exec(input, eid)?;

        Ok(())
    }
}

pub fn get_state<S, M, AP>(
    access_policy: AP,
    enclave_id: sgx_enclave_id_t,
    mem_name: &str,
) -> Result<S>
where
    S: State + TryFrom<Vec<u8>>,
    <S as TryFrom<Vec<u8>>>::Error: Debug,
    M: MemNameConverter,
    AP: AccessPolicy,
{
    let mem_id = M::as_id(mem_name);
    let input = host_input::GetState::new(access_policy, mem_id);

    let state = GetStateWorkflow::exec(input, enclave_id)?
        .ecall_output
        .unwrap()
        .into_vec()
        .try_into()
        .unwrap();

    Ok(state)
}
