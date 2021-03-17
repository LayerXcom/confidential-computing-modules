#[cfg(feature = "backup-enable")]
use crate::backup::SecretBackup;
use crate::workflow::*;
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    traits::*,
    utils::*,
    workflow::host_input,
};
use frame_host::engine::HostEngine;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{fmt::Debug, path::Path};
use web3::types::{Address, H256};

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher<S: Sender, W: Watcher> {
    inner: RwLock<InnerDispatcher<S, W>>,
}

#[derive(Debug)]
struct InnerDispatcher<S: Sender, W: Watcher> {
    node_url: String,
    enclave_id: sgx_enclave_id_t,
    sender: Option<S>,
    watcher: Option<W>,
    cache: EventCache,
    #[cfg(feature = "backup-enable")]
    backup: SecretBackup,
}

impl<S, W> Dispatcher<S, W>
where
    S: Sender,
    W: Watcher,
{
    pub fn new(enclave_id: sgx_enclave_id_t, node_url: &str, cache: EventCache) -> Result<Self> {
        let inner = RwLock::new(InnerDispatcher {
            enclave_id,
            node_url: node_url.to_string(),
            cache,
            sender: None,
            watcher: None,
            #[cfg(feature = "backup-enable")]
            backup: SecretBackup::default(),
        });

        Ok(Dispatcher { inner })
    }

    pub fn set_contract_address<P: AsRef<Path> + Copy>(
        &self,
        contract_addr: &str,
        abi_path: P,
    ) -> Result<()> {
        let mut inner = self.inner.write();
        let enclave_id = inner.enclave_id;
        let node_url = &inner.node_url;

        let contract_info = ContractInfo::new(abi_path, contract_addr);
        let sender = S::new(enclave_id, node_url, contract_info)?;
        let watcher = W::new(node_url, contract_info, inner.cache.clone())?;

        inner.sender = Some(sender);
        inner.watcher = Some(watcher);

        Ok(())
    }

    pub async fn join_group<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
        ecall_cmd: u32,
    ) -> Result<H256> {
        self.send_report_handshake(signer, gas, contract_addr, abi_path, ecall_cmd, "joinGroup")
            .await
    }

    pub async fn register_report<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
        ecall_cmd: u32,
    ) -> Result<H256> {
        self.set_contract_address(contract_addr, abi_path)?;

        let inner = self.inner.read();
        let eid = inner.enclave_id;
        let input = host_input::RegisterReport::new(signer, gas, ecall_cmd);
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
        ecall_cmd: u32,
    ) -> Result<H256> {
        self.send_report_handshake(
            signer,
            gas,
            contract_addr,
            abi_path,
            ecall_cmd,
            "updateMrenclave",
        )
        .await
    }

    async fn send_report_handshake<P: AsRef<Path> + Copy>(
        &self,
        signer: Address,
        gas: u64,
        contract_addr: &str,
        abi_path: P,
        ecall_cmd: u32,
        method: &str,
    ) -> Result<H256> {
        self.set_contract_address(contract_addr, abi_path)?;

        let inner = self.inner.read();
        let eid = inner.enclave_id;
        let input = host_input::JoinGroup::new(signer, gas, ecall_cmd);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        let tx_hash = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .send_report_handshake(&host_output, method)
            .await?;

        Ok(tx_hash)
    }

    pub async fn send_command(
        &self,
        ciphertext: SodiumCiphertext,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    ) -> Result<H256> {
        let inner = self.inner.read();
        let input = host_input::Command::new(ciphertext, signer, gas, ecall_cmd);
        let eid = inner.enclave_id;
        
        let st1 = std::time::SystemTime::now();
        println!("########## st1: {:?}", st1);
        let host_output = CommandWorkflow::exec(input, eid)?;

        let st6 = std::time::SystemTime::now();
        println!("########## st6: {:?}", st6);

        match &inner.sender {
            Some(s) => s.send_command(&host_output).await,
            None => Err(HostError::AddressNotSet),
        }
    }

    pub fn get_state(
        &self,
        ciphertext: SodiumCiphertext,
        ecall_cmd: u32,
    ) -> Result<serde_json::Value> {
        let eid = self.inner.read().enclave_id;
        let input = host_input::GetState::new(ciphertext, ecall_cmd);
        let state = GetStateWorkflow::exec(input, eid)?
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;

        let bytes: Vec<u8> = bincode::deserialize(&state.state.as_bytes())?;
        serde_json::from_slice(&bytes[..]).map_err(Into::into)
    }

    pub fn get_user_counter(
        &self,
        ciphertext: SodiumCiphertext,
        ecall_cmd: u32,
    ) -> Result<serde_json::Value> {
        let eid = self.inner.read().enclave_id;
        let input = host_input::GetUserCounter::new(ciphertext, ecall_cmd);
        let user_counter = GetUserCounterWorkflow::exec(input, eid)?
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;

        serde_json::to_value(user_counter.user_counter).map_err(Into::into)
    }

    pub async fn handshake(&self, signer: Address, gas: u64, ecall_cmd: u32) -> Result<H256> {
        let inner = self.inner.read();
        let input = host_input::Handshake::new(signer, gas, ecall_cmd);
        let eid = inner.enclave_id;
        let host_output = HandshakeWorkflow::exec(input, eid)?;

        let tx_hash = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .handshake(&host_output)
            .await?;

        Ok(tx_hash)
    }

    pub async fn fetch_events(
        &self,
        fetch_ciphertext_cmd: u32,
        fetch_handshake_cmd: u32,
    ) -> Result<Option<Vec<serde_json::Value>>> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        inner
            .watcher
            .as_ref()
            .ok_or(HostError::EventWatcherNotSet)?
            .fetch_events(eid, fetch_ciphertext_cmd, fetch_handshake_cmd)
            .await
    }

    pub async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        self.inner
            .read()
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .get_account(index, password)
            .await
    }

    pub fn get_enclave_encryption_key(&self, ecall_cmd: u32) -> Result<SodiumPubKey> {
        let input = host_input::GetEncryptionKey::new(ecall_cmd);
        let eid = self.inner.read().enclave_id;
        let enclave_encryption_key = GetEncryptionKeyWorkflow::exec(input, eid)?;

        Ok(enclave_encryption_key
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?
            .enclave_encryption_key())
    }

    pub fn register_notification(
        &self,
        ciphertext: SodiumCiphertext,
        ecall_cmd: u32,
    ) -> Result<()> {
        let inner = self.inner.read();
        let input = host_input::RegisterNotification::new(ciphertext, ecall_cmd);
        let eid = inner.enclave_id;
        let _host_output = RegisterNotificationWorkflow::exec(input, eid)?;

        Ok(())
    }

    #[cfg(feature = "backup-enable")]
    pub fn all_backup_to(&self, ecall_cmd: u32) -> Result<()> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        inner.backup.all_backup_to(eid, ecall_cmd)
    }

    #[cfg(feature = "backup-enable")]
    pub fn all_backup_from(&self, ecall_cmd: u32) -> Result<()> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        inner.backup.all_backup_from(eid, ecall_cmd)
    }
}
