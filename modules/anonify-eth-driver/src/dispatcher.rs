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
use opentelemetry::trace::TraceContextExt;
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{fmt::Debug, path::Path, sync::Arc, time};
use tracing::Span;
use tracing::{debug, error, info};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use web3::{
    contract::Options,
    types::{Address, TransactionReceipt, H256},
};

/// This dispatcher communicates with a blockchain node.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    inner: Arc<RwLock<InnerDispatcher>>,
}

#[derive(Debug)]
struct InnerDispatcher {
    node_url: String,
    enclave_id: sgx_enclave_id_t,
    confirmations: usize,
    sender: Option<EthSender>,
    watcher: Option<EventWatcher>,
    cache: EventCache,
    is_healthy: bool,
    #[cfg(feature = "backup-enable")]
    backup: SecretBackup,
    instance_id: String,
}

impl Dispatcher {
    pub fn new(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        confirmations: usize,
        cache: EventCache,
        instance_id: &str,
    ) -> Self {
        let inner = Arc::new(RwLock::new(InnerDispatcher {
            enclave_id,
            node_url: node_url.to_string(),
            confirmations,
            cache,
            sender: None,
            watcher: None,
            is_healthy: false,
            #[cfg(feature = "backup-enable")]
            backup: SecretBackup::default(),
            instance_id: instance_id.to_string(),
        }));

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
            if anonify_contract_address == Address::zero() {
                return Err(HostError::AnonifyAddressNotSet);
            }
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
    /// These operations are not mutable so just returning self data type.
    pub async fn run(
        self,
        sync_time: u64,
        signer: Address,
        gas: u64,
        fetch_ciphertext_ecall_cmd: u32,
        fetch_handshake_ecalll_cmd: Option<u32>,
        join_group_ecall_cmd: u32,
    ) -> Result<Self> {
        let this = self.clone();

        // it spawns a new OS thread, and hosts an event loop.
        actix_rt::Arbiter::new().exec_fn(move || {
            actix_rt::spawn(async move {
                loop {
                    match this
                        .fetch_events(fetch_ciphertext_ecall_cmd, fetch_handshake_ecalll_cmd)
                        .await
                    {
                        Ok(updated_states) => debug!("State updated: {:?}", updated_states),
                        Err(err) => error!("event fetched error: {:?}", err),
                    };
                    actix_rt::time::delay_for(time::Duration::from_millis(sync_time)).await;
                }
            });
        });

        // the second and the subsequent state-runtime nodes must receive handshakes predecessors sent before it joins
        actix_rt::time::delay_for(time::Duration::from_millis(sync_time)).await;
        let receipt = self.join_group(signer, gas, join_group_ecall_cmd).await?;
        info!("A transaction hash of join_group: {:?}", receipt);

        Ok(self)
    }

    pub fn set_healthy(self) -> Self {
        self.inner.write().is_healthy = true;
        self
    }

    pub fn is_healthy(&self) -> bool {
        self.inner.read().is_healthy
    }

    #[tracing::instrument(
        skip(self, fetch_ciphertext_ecall_cmd, fetch_handshake_ecall_cmd),
        fields(trace_id, fetched_trace_id, instance_id)
    )]
    pub async fn fetch_events(
        &self,
        fetch_ciphertext_ecall_cmd: u32,
        fetch_handshake_ecall_cmd: Option<u32>,
    ) -> Result<Option<Vec<serde_json::Value>>> {
        let trace_id = Span::current()
            .context()
            .span()
            .span_context()
            .trace_id()
            .to_hex();
        Span::current().record("trace_id", &tracing::field::display(trace_id));
        Span::current().record(
            "instance_id",
            &tracing::field::display(&self.inner.read().instance_id),
        );

        let inner = self.inner.read();
        let eid = inner.enclave_id;
        inner
            .watcher
            .as_ref()
            .ok_or(HostError::EventWatcherNotSet)?
            .fetch_events(eid, fetch_ciphertext_ecall_cmd, fetch_handshake_ecall_cmd)
            .await
    }

    pub async fn register_report(&self, signer: Address, gas: u64) -> Result<H256> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        let input = host_input::RegisterReport::new(signer, gas, SEND_REGISTER_REPORT_CMD);
        let host_output = RegisterReportWorkflow::exec(input, eid)?;

        let tx_hash = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .register_report(&host_output)
            .await?;

        Ok(tx_hash)
    }

    pub async fn join_group(
        &self,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    ) -> Result<TransactionReceipt> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        let input = host_input::JoinGroup::new(signer, gas, ecall_cmd);
        let host_output = JoinGroupWorkflow::exec(input, eid)?;

        let receipt = inner
            .sender
            .as_ref()
            .ok_or(HostError::AddressNotSet)?
            .join_group(&host_output, inner.confirmations)
            .await?;

        Ok(receipt)
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

    pub fn get_state(&self, ciphertext: SodiumCiphertext) -> Result<serde_json::Value> {
        let eid = self.inner.read().enclave_id;
        let input = host_input::GetState::new(ciphertext, GET_STATE_CMD);
        let state = GetStateWorkflow::exec(input, eid)?
            .ecall_output
            .ok_or(HostError::EcallOutputNotSet)?;

        let bytes: Vec<u8> = bincode::deserialize(&state.state.as_bytes())?;
        serde_json::from_slice(&bytes[..]).map_err(Into::into)
    }

    pub fn get_user_counter(&self, ciphertext: SodiumCiphertext) -> Result<serde_json::Value> {
        let eid = self.inner.read().enclave_id;
        let input = host_input::GetUserCounter::new(ciphertext, GET_USER_COUNTER_CMD);
        let user_counter = GetUserCounterWorkflow::exec(input, eid)?
            .ecall_output
            .ok_or(HostError::EcallOutputNotSet)?;

        serde_json::to_value(user_counter.user_counter).map_err(Into::into)
    }

    pub async fn handshake(&self, signer: Address, gas: u64) -> Result<H256> {
        let inner = self.inner.read();
        let input = host_input::Handshake::new(signer, gas, SEND_HANDSHAKE_TREEKEM_CMD);
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

    pub fn get_enclave_encryption_key(&self) -> Result<SodiumPubKey> {
        let input = host_input::GetEncryptionKey::new(GET_ENCLAVE_ENCRYPTION_KEY_CMD);
        let eid = self.inner.read().enclave_id;
        let enclave_encryption_key = GetEncryptionKeyWorkflow::exec(input, eid)?;

        Ok(enclave_encryption_key
            .ecall_output
            .ok_or(HostError::EcallOutputNotSet)?
            .enclave_encryption_key())
    }

    pub fn register_notification(&self, ciphertext: SodiumCiphertext) -> Result<()> {
        let inner = self.inner.read();
        let input = host_input::RegisterNotification::new(ciphertext, REGISTER_NOTIFICATION_CMD);
        let eid = inner.enclave_id;
        let _host_output = RegisterNotificationWorkflow::exec(input, eid)?;

        Ok(())
    }

    #[cfg(feature = "backup-enable")]
    pub fn all_backup_to(&self) -> Result<()> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        inner.backup.all_backup_to(eid, BACKUP_PATH_SECRET_ALL_CMD)
    }

    #[cfg(feature = "backup-enable")]
    pub fn all_backup_from(&self) -> Result<()> {
        let inner = self.inner.read();
        let eid = inner.enclave_id;
        inner
            .backup
            .all_backup_from(eid, RECOVER_PATH_SECRET_ALL_CMD)
    }
}
