use crate::{
    enclave_key::EnclaveKey,
    error::Result,
    group_key::GroupKey,
    kvs::{UserCounterDB, UserStateDB},
    notify::Notifier,
};
use anonify_ecall_types::*;
use anyhow::{anyhow, bail};
use frame_common::{
    crypto::AccountId,
    state_types::{
        MemId, NotifyState, ReturnState, StateCounter, StateType, UpdatedState, UserCounter,
    },
    AccessPolicy,
};
#[cfg(feature = "backup-enable")]
use frame_config::KEY_VAULT_ENCLAVE_MEASUREMENT;
use frame_config::{ANONIFY_PARAMS_DIR, IAS_ROOT_CERT, PATH_SECRETS_DIR};
use frame_enclave::EnclaveEngine;
#[cfg(feature = "backup-enable")]
use frame_mra_tls::{
    key_vault::{
        request::{
            BackupAllPathSecretsRequestBody, BackupPathSecretRequestBody, KeyVaultCmd,
            KeyVaultRequest, RecoverAllPathSecretsRequestbody, RecoverPathSecretRequestBody,
        },
        response::RecoveredPathSecret,
    },
    AttestedTlsConfig, Client, ClientConfig,
};
use frame_runtime::traits::*;
use frame_sodium::{SodiumCiphertext, SodiumPrivateKey, SodiumPubKey, StoreEnclaveDecryptionKey};
#[cfg(feature = "backup-enable")]
use frame_treekem::PathSecret;
use frame_treekem::{
    handshake::{PathSecretKVS, PathSecretSource},
    init_path_secret_kvs, StorePathSecrets,
};
use rand_core::{CryptoRng, RngCore};
use remote_attestation::{EncodedQuote, QuoteTarget};
use std::{
    env,
    prelude::v1::*,
    sync::{Arc, SgxRwLock, SgxRwLockReadGuard, SgxRwLockWriteGuard},
    vec::Vec,
};

/// spid: Service provider ID for the ISV.
#[derive(Clone)]
pub struct AnonifyEnclaveContext {
    version: usize,
    my_roster_idx: usize,
    ias_url: String,
    sub_key: String,
    #[cfg(feature = "backup-enable")]
    key_vault_endpoint: String,
    spid: String,
    enclave_key: EnclaveKey,
    user_state_db: UserStateDB,
    user_counter_db: UserCounterDB,
    notifier: Notifier,
    group_key: Arc<SgxRwLock<GroupKey>>,
    #[cfg(feature = "backup-enable")]
    client_config: ClientConfig,
    store_path_secrets: StorePathSecrets,
    store_enclave_dec_key: StoreEnclaveDecryptionKey,
    ias_root_cert: Vec<u8>,
    state_counter: Arc<SgxRwLock<StateCounter>>,
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

    #[cfg(feature = "backup-enable")]
    fn key_vault_endpoint(&self) -> &str {
        &self.key_vault_endpoint
    }

    fn spid(&self) -> &str {
        &self.spid
    }

    fn store_path_secrets(&self) -> &StorePathSecrets {
        &self.store_path_secrets
    }

    fn store_enclave_dec_key(&self) -> &StoreEnclaveDecryptionKey {
        &self.store_enclave_dec_key
    }

    fn ias_root_cert(&self) -> &[u8] {
        &self.ias_root_cert
    }

    fn my_roster_idx(&self) -> usize {
        self.my_roster_idx
    }
}

impl StateOps for AnonifyEnclaveContext {
    type S = StateType;

    fn values(self) -> Vec<Self::S> {
        self.user_state_db.values()
    }

    fn get_state_by_mem_id<U>(&self, key: U, mem_id: MemId) -> Self::S
    where
        U: Into<AccountId>,
    {
        self.user_state_db.get(key.into(), mem_id)
    }

    fn get_state_by_state_name<U, R, CTX>(
        ctx: CTX,
        cmd_name: &str,
        account_id: U,
        runtime_params: serde_json::Value,
    ) -> anyhow::Result<Self::S>
    where
        U: Into<AccountId>,
        R: RuntimeExecutor<CTX, S = Self::S>,
        CTX: ContextOps<S = Self::S>,
    {
        let call_kind = R::C::new(cmd_name, runtime_params)?;
        let res = R::new(ctx).execute(call_kind, account_id.into())?;

        match res {
            ReturnState::Updated(_) => Err(anyhow!(
                "Calling getting state function, but the called function is for state transition"
            )),
            ReturnState::Get(state) => Ok(state),
        }
    }

    fn get_user_counter<U>(&self, account_id: U) -> UserCounter
    where
        U: Into<AccountId>,
    {
        self.user_counter_db.get(account_id.into())
    }

    /// Returns a updated state of registerd account_id in notification.
    // TODO: Enables to return multiple updated states.
    fn update_state(
        &self,
        updated_state_iter: impl Iterator<Item = UpdatedState<Self::S>>,
        mut notify_state_iter: impl Iterator<Item = Option<NotifyState>>,
    ) -> Option<NotifyState> {
        updated_state_iter.for_each(|s| self.user_state_db.insert_by_updated_state(s));
        notify_state_iter
            .find(|state| {
                if let Some(s) = state {
                    self.is_notified(&s.account_id)
                } else {
                    // if the type of NotifyState is `Approved`
                    false
                }
            })
            .and_then(|e| e)
    }

    fn verify_state_counter_increment(
        &self,
        received_state_counter: StateCounter,
    ) -> anyhow::Result<()> {
        let mut curr_state_counter = self.state_counter.write().unwrap();
        if !curr_state_counter.is_increment(received_state_counter) {
            bail!(
                "Incremented stored state counter ({:?}) is not equal to a received state counter ({:?})",
                curr_state_counter.increment(),
                received_state_counter,
            );
        }
        *curr_state_counter = curr_state_counter.increment();

        Ok(())
    }

    fn verify_user_counter_increment(
        &self,
        user: AccountId,
        received: UserCounter,
    ) -> anyhow::Result<()> {
        self.user_counter_db
            .increment(user, received)
            .map_err(|e| anyhow!("{:?}", e))
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

impl EnclaveKeyOps for AnonifyEnclaveContext {
    /// Generate a signature using enclave signing key.
    /// This signature is used to verify enclave's program dependencies and
    /// should be verified in the public available place such as smart contract on blockchain.
    fn sign(&self, msg: &[u8]) -> anyhow::Result<(secp256k1::Signature, secp256k1::RecoveryId)> {
        self.enclave_key.sign(msg).map_err(Into::into)
    }

    fn decrypt(&self, ciphertext: &SodiumCiphertext) -> anyhow::Result<Vec<u8>> {
        self.enclave_key.decrypt(ciphertext).map_err(Into::into)
    }

    fn enclave_encryption_key(&self) -> anyhow::Result<SodiumPubKey> {
        self.enclave_key
            .enclave_encryption_key()
            .map_err(|e| anyhow!("{:?}", e))
    }

    fn enclave_decryption_key(&self) -> anyhow::Result<&SodiumPrivateKey> {
        self.enclave_key
            .enclave_decryption_key()
            .map_err(|e| anyhow!("{:?}", e))
    }
}

impl QuoteGetter for AnonifyEnclaveContext {
    fn quote(&self) -> anyhow::Result<EncodedQuote> {
        let report_data = &self.enclave_key.report_data()?;
        QuoteTarget::new()?
            .set_enclave_report(&report_data)?
            .create_quote(&self.spid)
            .map_err(|e| anyhow!("{:?}", e))
    }
}

#[cfg(feature = "backup-enable")]
impl KeyVaultOps for AnonifyEnclaveContext {
    fn backup_path_secret(
        &self,
        backup_path_secret: BackupPathSecretRequestBody,
    ) -> anyhow::Result<()> {
        let mut mra_tls_client = Client::new(self.key_vault_endpoint(), &self.client_config)?;
        let key_vault_request =
            KeyVaultRequest::new(KeyVaultCmd::StorePathSecret, backup_path_secret);
        let _resp: serde_json::Value = mra_tls_client.send_json(key_vault_request)?;

        Ok(())
    }

    fn recover_path_secret(&self, ps_id: &[u8], roster_idx: u32) -> anyhow::Result<PathSecret> {
        let recover_request = RecoverPathSecretRequestBody::new(roster_idx, ps_id.to_vec());
        let mut mra_tls_client = Client::new(self.key_vault_endpoint(), &self.client_config)?;
        let backup_request = KeyVaultRequest::new(KeyVaultCmd::RecoverPathSecret, recover_request);
        let recovered_path_secret: RecoveredPathSecret =
            mra_tls_client.send_json(backup_request)?;

        Ok(PathSecret::from(recovered_path_secret.path_secret()))
    }

    fn manually_backup_path_secrets_all(
        &self,
        backup_path_secrets: BackupAllPathSecretsRequestBody,
    ) -> anyhow::Result<()> {
        let mut mra_tls_client = Client::new(self.key_vault_endpoint(), &self.client_config)?;
        let key_vault_request = KeyVaultRequest::new(
            KeyVaultCmd::ManuallyStoreAllPathSecrets,
            backup_path_secrets,
        );
        let _resp: serde_json::Value = mra_tls_client.send_json(key_vault_request)?;

        Ok(())
    }

    fn manually_recover_path_secrets_all(
        &self,
        recover_path_secrets_all: RecoverAllPathSecretsRequestbody,
    ) -> anyhow::Result<Vec<RecoveredPathSecret>> {
        let mut mra_tls_client = Client::new(self.key_vault_endpoint(), &self.client_config)?;
        let key_vault_request = KeyVaultRequest::new(
            KeyVaultCmd::ManuallyRecoverAllPathSecrets,
            recover_path_secrets_all,
        );
        let path_secrets: Vec<RecoveredPathSecret> = mra_tls_client.send_json(key_vault_request)?;

        Ok(path_secrets)
    }
}

// TODO: Consider SGX_ERROR_BUSY.
impl AnonifyEnclaveContext {
    pub fn new<R: RngCore + CryptoRng>(version: usize, rng: &mut R) -> Result<Self> {
        let user_state_db = UserStateDB::new();
        let user_counter_db = UserCounterDB::new();

        let source = match env::var("AUDITOR_ENDPOINT") {
            Err(_) => PathSecretSource::Local,
            // just for unit testing (test_app_msg_correctness)
            #[cfg(debug_assertions)]
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

        #[cfg(feature = "backup-enable")]
        let key_vault_endpoint = env::var("KEY_VAULT_ENDPOINT_FOR_STATE_RUNTIME")
            .expect("KEY_VAULT_ENDPOINT_FOR_STATE_RUNTIME is not set");

        #[cfg(feature = "backup-enable")]
        let client_config = {
            let attested_tls_config = AttestedTlsConfig::new_by_ra(
                &spid,
                &ias_url.clone(),
                &sub_key.clone(),
                IAS_ROOT_CERT.to_vec(),
            )?;
            ClientConfig::from_attested_tls_config(attested_tls_config)?
                .set_attestation_report_verifier(
                    IAS_ROOT_CERT.to_vec(),
                    *KEY_VAULT_ENCLAVE_MEASUREMENT,
                )
        };

        let store_path_secrets = StorePathSecrets::new(&*PATH_SECRETS_DIR);
        let store_enclave_dec_key = StoreEnclaveDecryptionKey::new(&*ANONIFY_PARAMS_DIR);
        let state_counter = Arc::new(SgxRwLock::new(StateCounter::default()));

        let enclave_key = {
            let enc_key = EnclaveKey::new()?;
            // Trying set the enclave decryption key from local storage.
            match enc_key
                .clone()
                .get_dec_key_from_locally_sealed(&store_enclave_dec_key)
            {
                Ok(enclave_key) => enclave_key,
                // If not, trying set the key from remote key-vault node.
                Err(_e) => {
                    // If the backup enabled, try to fetch the enclave decryption key from the remote key_vault node.
                    #[cfg(feature = "backup-enable")]
                    match enc_key
                        .clone()
                        .get_dec_key_from_remotelly_sealed(&client_config, &key_vault_endpoint)
                    {
                        Ok(enclave_key) => enclave_key,
                        Err(_e) => {
                            // new anonify group will be created.
                            if my_roster_idx == 0 {
                                enc_key.get_new_gen_dec_key(rng)?
                            } else {
                                // should panic because it failed when initializing the node.
                                panic!("The node cannot be initialized because there is no Enclave decryption key either locally or remotely.");
                            }
                        }
                    }

                    // If the backup disabled, generate a new Enclave decryption key on each node.
                    #[cfg(not(feature = "backup-enable"))]
                    enc_key.get_new_gen_dec_key(rng)?
                }
            }
        };

        enclave_key.store_dec_key_to_local(&store_enclave_dec_key)?;
        #[cfg(feature = "backup-enable")]
        enclave_key.store_dec_key_to_remote(&client_config, &key_vault_endpoint)?;

        Ok(AnonifyEnclaveContext {
            spid,
            enclave_key,
            user_state_db,
            user_counter_db,
            notifier,
            group_key,
            version,
            my_roster_idx,
            ias_url,
            sub_key,
            #[cfg(feature = "backup-enable")]
            key_vault_endpoint,
            #[cfg(feature = "backup-enable")]
            client_config,
            store_path_secrets,
            store_enclave_dec_key,
            ias_root_cert: (&*IAS_ROOT_CERT).to_vec(),
            state_counter,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetState<AP: AccessPolicy> {
    ecall_input: input::GetState<AP>,
}

impl<AP: AccessPolicy> EnclaveEngine for GetState<AP> {
    type EI = SodiumCiphertext;
    type EO = output::ReturnState;

    fn decrypt<C>(ciphertext: Self::EI, enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let buf = enclave_context.decrypt(&ciphertext)?;
        let ecall_input = serde_json::from_slice(&buf[..])?;

        Ok(Self { ecall_input })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        self.ecall_input.access_policy().verify()
    }

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let input::GetState {
            access_policy,
            runtime_params,
            state_name,
        } = self.ecall_input;
        let user_state = C::get_state_by_state_name::<_, R, _>(
            enclave_context.clone(),
            &state_name,
            access_policy.into_account_id(),
            runtime_params,
        )?;

        Ok(output::ReturnState::new(user_state))
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetUserCounter<AP: AccessPolicy> {
    ecall_input: input::GetUserCounter<AP>,
}

impl<AP: AccessPolicy> EnclaveEngine for GetUserCounter<AP> {
    type EI = SodiumCiphertext;
    type EO = output::ReturnUserCounter;

    fn decrypt<C>(ciphertext: Self::EI, enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let buf = enclave_context.decrypt(&ciphertext)?;
        let ecall_input = serde_json::from_slice(&buf[..])?;

        Ok(Self { ecall_input })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        self.ecall_input.access_policy().verify()
    }

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let account_id = self.ecall_input.access_policy().into_account_id();
        let user_counter = enclave_context.get_user_counter(account_id);

        Ok(output::ReturnUserCounter::new(user_counter))
    }
}

/// A report registration engine
#[derive(Debug, Clone, Default)]
pub struct ReportRegistration;

impl EnclaveEngine for ReportRegistration {
    type EI = input::Empty;
    type EO = output::ReturnRegisterReport;

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
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
