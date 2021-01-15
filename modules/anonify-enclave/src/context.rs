use crate::{
    error::Result, group_key::GroupKey, identity_key::EnclaveIdentityKey, kvs::EnclaveDB,
    notify::Notifier,
};
use anonify_config::{ENCLAVE_MEASUREMENT_KEY_VAULT, IAS_ROOT_CERT};
use anonify_io_types::*;
use anyhow::anyhow;
use frame_common::{
    crypto::{
        AccountId, BackupPathSecret, KeyVaultCmd, KeyVaultRequest, RecoverAllRequest,
        RecoveredPathSecret,
    },
    state_types::{MemId, ReturnState, StateType, UpdatedState},
    AccessPolicy,
};
use frame_enclave::EnclaveEngine;
use frame_mra_tls::{AttestedTlsConfig, Client, ClientConfig};
use frame_runtime::traits::*;
use frame_treekem::{
    handshake::{PathSecretKVS, PathSecretSource},
    init_path_secret_kvs, DhPubKey, EciesCiphertext, StorePathSecrets,
};
use frame_config::PATH_SECRETS_DIR;
use remote_attestation::{EncodedQuote, QuoteTarget};
use std::{
    env,
    marker::PhantomData,
    prelude::v1::*,
    sync::{Arc, SgxRwLock, SgxRwLockReadGuard, SgxRwLockWriteGuard},
    vec::Vec,
};

/// spid: Service provider ID for the ISV.
#[derive(Clone)]
pub struct AnonifyEnclaveContext {
    version: usize,
    ias_url: String,
    sub_key: String,
    key_vault_endpoint: String,
    spid: String,
    identity_key: EnclaveIdentityKey,
    db: EnclaveDB,
    notifier: Notifier,
    group_key: Arc<SgxRwLock<GroupKey>>,
    client_config: ClientConfig,
    store_path_secrets: StorePathSecrets,
}

impl ConfigGetter for AnonifyEnclaveContext {
    fn mrenclave_ver(&self) -> usize {
        self.version
    }

    fn ias_url(&self) -> &str {
        &self.ias_url
    }

    fn sub_key(&self) -> &str {
        &self.sub_key
    }

    fn key_vault_endpoint(&self) -> &str {
        &self.key_vault_endpoint
    }

    fn spid(&self) -> &str {
        &self.spid
    }

    fn store_path_secrets(&self) -> &StorePathSecrets {
        &self.store_path_secrets
    }
}

impl StateOps for AnonifyEnclaveContext {
    type S = StateType;

    fn values(self) -> Vec<Self::S> {
        self.db.values()
    }

    fn get_state_by_mem_id<U>(&self, key: U, mem_id: MemId) -> Self::S
    where
        U: Into<AccountId>,
    {
        self.db.get(key.into(), mem_id)
    }

    fn get_state_by_call_id<U, R, CTX>(
        ctx: CTX,
        call_id: u32,
        account_id: U,
    ) -> anyhow::Result<Self::S>
    where
        U: Into<AccountId>,
        R: RuntimeExecutor<CTX, S = Self::S>,
        CTX: ContextOps<S = Self::S>,
    {
        let mut empty_params = vec![];
        let call_kind = R::C::new(call_id, &mut empty_params)?;
        let res = R::new(ctx).execute(call_kind, account_id.into())?;

        match res {
            ReturnState::Updated(_) => Err(anyhow!(
                "Calling getting state function, but the called function is for state transition"
            )),
            ReturnState::Get(state) => Ok(state),
        }
    }

    /// Returns a updated state of registerd account_id in notification.
    // TODO: Enables to return multiple updated states.
    fn update_state(
        &self,
        mut state_iter: impl Iterator<Item = UpdatedState<Self::S>> + Clone,
    ) -> Option<UpdatedState<Self::S>> {
        state_iter
            .clone()
            .for_each(|s| self.db.insert_by_updated_state(s));
        state_iter.find(|s| self.is_notified(&s.account_id))
    }
}

impl GroupKeyGetter for AnonifyEnclaveContext {
    type GK = GroupKey;

    fn read_group_key(&self) -> SgxRwLockReadGuard<Self::GK> {
        self.group_key.read().unwrap()
    }

    fn write_group_key(&self) -> SgxRwLockWriteGuard<Self::GK> {
        self.group_key.write().unwrap()
    }
}

impl NotificationOps for AnonifyEnclaveContext {
    fn set_notification(&self, account_id: AccountId) -> bool {
        self.notifier.register(account_id)
    }

    fn is_notified(&self, account_id: &AccountId) -> bool {
        self.notifier.contains(&account_id)
    }
}

impl IdentityKeyOps for AnonifyEnclaveContext {
    /// Generate a signature using enclave's identity key.
    /// This signature is used to verify enclave's program dependencies and
    /// should be verified in the public available place such as smart contract on blockchain.
    fn sign(&self, msg: &[u8]) -> anyhow::Result<(secp256k1::Signature, secp256k1::RecoveryId)> {
        self.identity_key.sign(msg).map_err(Into::into)
    }

    fn decrypt(&self, ciphertext: EciesCiphertext) -> anyhow::Result<Vec<u8>> {
        self.identity_key.decrypt(ciphertext).map_err(Into::into)
    }

    fn encrypting_key(&self) -> DhPubKey {
        self.identity_key.encrypting_key()
    }
}

impl QuoteGetter for AnonifyEnclaveContext {
    fn quote(&self) -> anyhow::Result<EncodedQuote> {
        let report_data = &self.identity_key.report_data()?;
        QuoteTarget::new()?
            .set_enclave_report(&report_data)?
            .create_quote(&self.spid)
            .map_err(|e| anyhow!("{:?}", e))
    }
}

impl KeyVaultOps for AnonifyEnclaveContext {
    fn backup_path_secret(&self, backup_path_secret: BackupPathSecret) -> anyhow::Result<()> {
        let mut mra_tls_client =
            Client::new(self.key_vault_endpoint(), &self.client_config).unwrap();
        let key_vault_request = KeyVaultRequest::new(KeyVaultCmd::Store, backup_path_secret);
        let _resp: serde_json::Value = mra_tls_client.send_json(key_vault_request)?;

        Ok(())
    }

    fn manually_backup_path_secrets_all(
        &self,
        backup_path_secrets: Vec<BackupPathSecret>,
    ) -> anyhow::Result<()> {
        let mut mra_tls_client =
            Client::new(self.key_vault_endpoint(), &self.client_config).unwrap();
        let key_vault_request =
            KeyVaultRequest::new(KeyVaultCmd::ManuallyStoreAll, backup_path_secrets);
        let _resp: serde_json::Value = mra_tls_client.send_json(key_vault_request)?;

        Ok(())
    }

    fn manually_recover_path_secrets_all(
        &self,
        recover_path_secrets_all: RecoverAllRequest,
    ) -> anyhow::Result<Vec<RecoveredPathSecret>> {
        let mut mra_tls_client =
            Client::new(self.key_vault_endpoint(), &self.client_config).unwrap();
        let key_vault_request =
            KeyVaultRequest::new(KeyVaultCmd::ManuallyRecoverAll, recover_path_secrets_all);
        let path_secrets: Vec<RecoveredPathSecret> = mra_tls_client.send_json(key_vault_request)?;

        Ok(path_secrets)
    }
}

// TODO: Consider SGX_ERROR_BUSY.
impl AnonifyEnclaveContext {
    pub fn new(version: usize) -> Result<Self> {
        let identity_key = EnclaveIdentityKey::new()?;
        let db = EnclaveDB::new();

        let source = match env::var("AUDITOR_ENDPOINT") {
            Err(_) => PathSecretSource::Local,
            Ok(test) if test == "test" => {
                const UNTIL_ROSTER_IDX: usize = 10;
                const UNTIL_EPOCH: usize = 30;
                let mut kvs = PathSecretKVS::new();
                init_path_secret_kvs(&mut kvs, UNTIL_ROSTER_IDX, UNTIL_EPOCH);
                PathSecretSource::LocalTestKV(kvs)
            }
            Ok(url) => PathSecretSource::Remote(url),
        };

        let spid = env::var("SPID").expect("SPID is not set");
        let my_roster_idx: usize = env::var("MY_ROSTER_IDX")
            .expect("MY_ROSTER_IDX is not set")
            .parse()
            .expect("Failed to parse MY_ROSTER_IDX to usize");
        let max_roster_idx: usize = env::var("MAX_ROSTER_IDX")
            .expect("MAX_ROSTER_IDX is not set")
            .parse()
            .expect("Failed to parse MAX_ROSTER_IDX to usize");

        let group_key = Arc::new(SgxRwLock::new(GroupKey::new(
            my_roster_idx,
            max_roster_idx,
            source,
        )?));
        let notifier = Notifier::new();

        let ias_url = env::var("IAS_URL").expect("IAS_URL is not set");
        let sub_key = env::var("SUB_KEY").expect("SUB_KEY is not set");
        let key_vault_endpoint =
            env::var("KEY_VAULT_ENDPOINT").expect("KEY_VAULT_ENDPOINT is not set");

        let attested_tls_config =
            AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec())?;
        let client_config = ClientConfig::from_attested_tls_config(attested_tls_config)?
            .set_attestation_report_verifier(
                IAS_ROOT_CERT.to_vec(),
                *ENCLAVE_MEASUREMENT_KEY_VAULT,
            );
        let store_path_secrets = StorePathSecrets::new(&*PATH_SECRETS_DIR);

        Ok(AnonifyEnclaveContext {
            spid,
            identity_key,
            db,
            notifier,
            group_key,
            version,
            ias_url,
            sub_key,
            key_vault_endpoint,
            client_config,
            store_path_secrets,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GetState<AP: AccessPolicy> {
    phantom: PhantomData<AP>,
}

impl<AP: AccessPolicy> EnclaveEngine for GetState<AP> {
    type EI = input::GetState<AP>;
    type EO = output::ReturnState;

    fn eval_policy(ecall_input: &Self::EI) -> anyhow::Result<()> {
        ecall_input.access_policy().verify()
    }

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let account_id = ecall_input.access_policy().into_account_id();
        let user_state = C::get_state_by_call_id::<_, R, _>(
            enclave_context.clone(),
            ecall_input.call_id(),
            account_id,
        )?;

        Ok(output::ReturnState::new(user_state))
    }
}

/// A report registration engine
#[derive(Debug, Clone)]
pub struct ReportRegistration;

impl EnclaveEngine for ReportRegistration {
    type EI = input::CallRegisterReport;
    type EO = output::ReturnRegisterReport;

    fn handle<R, C>(
        _ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let attested_report = enclave_context.quote()?.remote_attestation(
            ias_url,
            sub_key,
            IAS_ROOT_CERT.to_vec(),
        )?;

        let mrenclave_ver = enclave_context.mrenclave_ver();
        let my_roster_idx = enclave_context.read_group_key().my_roster_idx();

        Ok(output::ReturnRegisterReport::new(
            attested_report.report().to_vec(),
            attested_report.report_sig().to_vec(),
            mrenclave_ver,
            my_roster_idx,
        ))
    }
}
