use crate::workflow::*;
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    traits::*,
    utils::*,
    workflow::host_input,
};
use frame_common::{state_types::UpdatedState, traits::*};
use frame_host::engine::HostEngine;
use frame_treekem::{DhPubKey, EciesCiphertext};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{fmt::Debug, marker::Send, path::Path};
use web3::types::{Address, H256};

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<D: Deployer, S: Sender, W: Watcher> {
    inner: RwLock<InnerDispatcher<D, S, W>>,
}

#[derive(Debug)]
struct InnerDispatcher<D: Deployer, S: Sender, W: Watcher> {
    deployer: D,
    sender: Option<S>,
    watcher: Option<W>,
    cache: EventCache,
}

impl<D, S, W> Dispatcher<D, S, W>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    pub fn new(enclave_id: sgx_enclave_id_t, node_url: &str, cache: EventCache) -> Result<Self> {
        let deployer = D::new(enclave_id, node_url)?;
        let inner = RwLock::new(InnerDispatcher {
            deployer,
            cache,
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
        let watcher = W::new(node_url, contract_info, inner.cache.clone())?;

        inner.sender = Some(sender);
        inner.watcher = Some(watcher);

        Ok(())
    }

    pub async fn deploy<P: AsRef<Path> + Send>(
        &self,
        deploy_user: Address,
        gas: u64,
        abi_path: P,
        bin_path: P,
        confirmations: usize,
    ) -> Result<String> {
        let mut inner = self.inner.write();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::JoinGroup::new(deploy_user, gas);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        let contract_addr = inner
            .deployer
            .deploy(host_output.clone(), abi_path, bin_path, confirmations)
            .await?;
        Ok(contract_addr)
    }

    pub async fn join_group<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<H256> {
        self.send_report_handshake(signer, gas, contract_addr, abi_path, "joinGroup")
            .await
    }

    pub async fn register_report<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<H256> {
        self.set_contract_addr(contract_addr, abi_path)?;

        let inner = self.inner.read();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::RegisterReport::new(signer, gas);
        let host_output = RegisterReportWorkflow::exec(input, eid)?;

        let tx_hash = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .register_report(&host_output)
            .await?;

        Ok(tx_hash)
    }

    pub async fn update_mrenclave<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<H256> {
        self.send_report_handshake(signer, gas, contract_addr, abi_path, "updateMrenclave")
            .await
    }

    async fn send_report_handshake<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
        method: &str,
    ) -> Result<H256> {
        self.set_contract_addr(contract_addr, abi_path)?;

        let inner = self.inner.read();
        let eid = inner.deployer.get_enclave_id();
        let input = host_input::JoinGroup::new(signer, gas);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        let tx_hash = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .send_report_handshake(&host_output, method)
            .await?;

        Ok(tx_hash)
    }

    pub async fn send_command<C, AP>(
        &self,
        access_policy: AP,
        encrypted_command: EciesCiphertext,
        call_name: &str,
        signer: Address,
        gas: u64,
    ) -> Result<H256>
    where
        C: CallNameConverter,
        AP: AccessPolicy,
    {
        let inner = self.inner.read();
        let input = host_input::Command::<C, AP>::new(
            encrypted_command,
            call_name.to_string(),
            access_policy,
            signer,
            gas,
        );
        let eid = inner.deployer.get_enclave_id();
        let host_output = CommandWorkflow::exec(input, eid)?;

        match &inner.sender {
            Some(s) => s.send_command(&host_output).await,
            None => Err(HostError::AddressNotSet),
        }
    }

    pub fn get_state<ST, AP, C>(&self, access_policy: AP, call_name: &str) -> Result<ST>
    where
        ST: State + StateDecoder,
        AP: AccessPolicy,
        C: CallNameConverter,
    {
        let call_id = C::as_id(call_name);
        let eid = self.inner.read().deployer.get_enclave_id();
        let input = host_input::GetState::new(access_policy, call_id);

        let vec = GetStateWorkflow::exec(input, eid)?
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?
            .into_vec(); // into Vec<u8> in StateType

        ST::decode_vec(vec).map_err(Into::into)
    }

    pub async fn handshake(&self, signer: Address, gas: u64) -> Result<H256> {
        let inner = self.inner.read();
        let input = host_input::Handshake::new(signer, gas);
        let eid = inner.deployer.get_enclave_id();
        let host_output = HandshakeWorkflow::exec(input, eid)?;

        let tx_hash = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .handshake(&host_output)
            .await?;

        Ok(tx_hash)
    }

    pub async fn fetch_events<St>(&self) -> Result<Option<Vec<UpdatedState<St>>>>
    where
        St: State,
    {
        let inner = self.inner.read();
        let eid = inner.deployer.get_enclave_id();
        inner
            .watcher
            .as_ref()
            .ok_or(HostError::EventWatcherNotSet)?
            .fetch_events(eid)
            .await
    }

    pub async fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.inner
            .read()
            .deployer
            .get_account(index, password)
            .await
    }

    pub fn get_encrypting_key(&self) -> Result<DhPubKey> {
        let input = host_input::GetEncryptingKey::default();
        let eid = self.inner.read().deployer.get_enclave_id();
        let encrypting_key = GetEncryptingKeyWorkflow::exec(input, eid)?;

        Ok(encrypting_key
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?
            .encrypting_key())
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
