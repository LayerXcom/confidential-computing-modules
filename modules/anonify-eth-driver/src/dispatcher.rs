#[cfg(feature = "backup-enable")]
use crate::backup::SecretBackup;
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    eth::{EthSender, EventWatcher},
    utils::*,
    workflow::*,
};
use anonify_ecall_types::cmd::*;
use frame_common::crypto::AccountId;
use frame_host::engine::HostEngine;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{fmt::Debug, path::Path, time};
use tracing::{error, info};
use web3::{
    contract::Options,
    types::{Address, H256},
};

/// This dispatcher communicates with a blockchain node.
#[derive(Debug)]
pub struct Dispatcher {
    inner: RwLock<InnerDispatcher>,
}

#[derive(Debug)]
struct InnerDispatcher {
    node_url: String,
    enclave_id: sgx_enclave_id_t,
    sender: Option<EthSender>,
    watcher: Option<EventWatcher>,
    cache: EventCache,
    #[cfg(feature = "backup-enable")]
    backup: SecretBackup,
}

impl Dispatcher {
    pub fn new(enclave_id: sgx_enclave_id_t, node_url: &str, cache: EventCache) -> Self {
        let inner = RwLock::new(InnerDispatcher {
            enclave_id,
            node_url: node_url.to_string(),
            cache,
            sender: None,
            watcher: None,
            #[cfg(feature = "backup-enable")]
            backup: SecretBackup::default(),
        });

        Dispatcher { inner }
    }

    pub async fn set_anonify_contract_address<P: AsRef<Path> + Copy>(
        self,
        factory_abi_path: P,
        factory_contract_address: Address,
        anonify_abi_path: P,
    ) -> Result<Self> {
        {
            let mut inner = self.inner.write();
            let contract = create_contract_interface(
                &inner.node_url,
                factory_abi_path,
                factory_contract_address,
            )?;
            let anonify_contract_address: Address = contract
                .query("getAnonifyAddress", (), None, Options::default(), None)
                .await?;
            let anonify_contract_info =
                ContractInfo::new(anonify_abi_path, anonify_contract_address)?;

            let sender = EthSender::new(
                inner.enclave_id,
                &inner.node_url,
                anonify_contract_info.clone(),
            )?;
            let watcher =
                EventWatcher::new(&inner.node_url, anonify_contract_info, inner.cache.clone())?;
            inner.sender = Some(sender);
            inner.watcher = Some(watcher);
        }

        Ok(self)
    }

    pub fn get_anonify_contract_address(&self) -> Result<Address> {
        let inner = self.inner.read();
        let address = inner
            .sender
            .as_ref()
            .ok_or_else(|| HostError::AddressNotSet)?
            .get_contract()
            .address();
        Ok(address)
    }

    /// - Starting syncing with the blockchain node.
    /// - Joining as the state runtime node.
    pub async fn run(self, sync_time: u64, signer: Address, gas: u64) -> Result<()> {
        let tx_hash = self.join_group(signer, gas, JOIN_GROUP_CMD).await?;
        info!("A transaction hash of join_group: {:?}", tx_hash);

        // it spawns a new OS thread, and hosts an event loop.
        actix_rt::Arbiter::new().exec_fn(move || {
            actix_rt::spawn(async move {
                loop {
                    match self
                        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
                        .await
                    {
                        Ok(updated_states) => info!("State updated: {:?}", updated_states),
                        Err(err) => error!("event fetched error: {:?}", err),
                    };
                    actix_rt::time::delay_for(time::Duration::from_millis(sync_time)).await;
                }
            });
        });

        Ok(())
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

    pub async fn join_group(&self, signer: Address, gas: u64, ecall_cmd: u32) -> Result<H256> {
        self.send_report_handshake(signer, gas, ecall_cmd, "joinGroup")
            .await
    }

    pub async fn register_report(&self, signer: Address, gas: u64, ecall_cmd: u32) -> Result<H256> {
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

    pub async fn update_mrenclave(
        &self,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    ) -> Result<H256> {
        self.send_report_handshake(signer, gas, ecall_cmd, "updateMrenclave")
            .await
    }

    async fn send_report_handshake(
        &self,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
        method: &str,
    ) -> Result<H256> {
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
        user_id: Option<AccountId>,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    ) -> Result<H256> {
        let inner = self.inner.read();
        let input = host_input::Command::new(ciphertext, user_id, signer, gas, ecall_cmd);
        let eid = inner.enclave_id;
        let host_output = CommandWorkflow::exec(input, eid)?;

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
