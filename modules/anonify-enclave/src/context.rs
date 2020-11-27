use crate::{
    error::Result, group_key::GroupKey, identity_key::EnclaveIdentityKey, kvs::EnclaveDB,
    notify::Notifier,
};
use anonify_io_types::*;
use anyhow::anyhow;
use frame_common::{
    crypto::{AccountId, ClientCiphertext},
    state_types::{MemId, ReturnState, StateType, UpdatedState},
    AccessPolicy,
};
use frame_enclave::{
    ocalls::{get_quote, sgx_init_quote},
    EnclaveEngine,
};
use frame_runtime::traits::*;
use frame_treekem::{
    handshake::{PathSecretKVS, PathSecretSource},
    init_path_secret_kvs,
};
use remote_attestation::RAService;
use sgx_types::*;
use sodiumoxide::crypto::box_::PublicKey as SodiumPublicKey;
use std::prelude::v1::*;
use std::{
    env,
    marker::PhantomData,
    sync::{Arc, SgxRwLock, SgxRwLockReadGuard, SgxRwLockWriteGuard},
};

pub const MRENCLAVE_VERSION: usize = 0;

/// spid: Service provider ID for the ISV.
#[derive(Clone)]
pub struct EnclaveContext {
    version: usize,
    ias_url: String,
    sub_key: String,
    spid: sgx_spid_t,
    identity_key: EnclaveIdentityKey,
    db: EnclaveDB,
    notifier: Notifier,
    group_key: Arc<SgxRwLock<GroupKey>>,
}

impl ContextOps for EnclaveContext {
    fn mrenclave_ver(&self) -> usize {
        self.version
    }

    fn ias_url(&self) -> &str {
        &self.ias_url
    }

    fn sub_key(&self) -> &str {
        &self.sub_key
    }
}

impl StateOps for EnclaveContext {
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

impl GroupKeyGetter for EnclaveContext {
    type GK = GroupKey;

    fn read_group_key(&self) -> SgxRwLockReadGuard<Self::GK> {
        self.group_key.read().unwrap()
    }

    fn write_group_key(&self) -> SgxRwLockWriteGuard<Self::GK> {
        self.group_key.write().unwrap()
    }
}

impl NotificationOps for EnclaveContext {
    fn set_notification(&self, account_id: AccountId) -> bool {
        self.notifier.register(account_id)
    }

    fn is_notified(&self, account_id: &AccountId) -> bool {
        self.notifier.contains(&account_id)
    }
}

impl IdentityKeyOps for EnclaveContext {
    /// Generate a signature using enclave's identity key.
    /// This signature is used to verify enclave's program dependencies and
    /// should be verified in the public available place such as smart contract on blockchain.
    fn sign(&self, msg: &[u8]) -> anyhow::Result<(secp256k1::Signature, secp256k1::RecoveryId)> {
        self.identity_key.sign(msg).map_err(Into::into)
    }

    fn decrypt(&self, ciphertext: ClientCiphertext) -> anyhow::Result<Vec<u8>> {
        self.identity_key.decrypt(ciphertext).map_err(Into::into)
    }

    fn encrypting_key(&self) -> SodiumPublicKey {
        self.identity_key.encrypting_key()
    }
}

impl QuoteGetter for EnclaveContext {
    fn quote(&self) -> anyhow::Result<String> {
        let target_info = self.init_quote()?;
        let report = self.report(&target_info)?;
        self.encoded_quote(report).map_err(Into::into)
    }
}

// TODO: Consider SGX_ERROR_BUSY.
impl EnclaveContext {
    pub fn new(spid: &str) -> Result<Self> {
        let spid_vec = hex::decode(spid)?;
        let mut id = [0; 16];
        id.copy_from_slice(&spid_vec);
        let spid: sgx_spid_t = sgx_spid_t { id };

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

        let ias_url = env::var("IAS_URL")?;
        let sub_key = env::var("SUB_KEY")?;

        Ok(EnclaveContext {
            spid,
            identity_key,
            db,
            notifier,
            group_key,
            version: MRENCLAVE_VERSION,
            ias_url,
            sub_key,
        })
    }

    pub(crate) fn init_quote(&self) -> Result<sgx_target_info_t> {
        let target_info = sgx_init_quote()?;
        Ok(target_info)
    }

    /// Return Attestation report
    fn report(&self, target_info: &sgx_target_info_t) -> Result<sgx_report_t> {
        let mut report = sgx_report_t::default();
        let report_data = &self.identity_key.report_data()?;

        if let Ok(r) = sgx_tse::rsgx_create_report(&target_info, &report_data) {
            report = r;
        }

        Ok(report)
    }

    fn encoded_quote(&self, report: sgx_report_t) -> Result<String> {
        let quote = get_quote(report, &self.spid)?;

        // Use base64-encoded QUOTE structure to communicate via defined API.
        Ok(base64::encode(&quote))
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
        let quote = enclave_context.quote()?;
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let (report, report_sig) = RAService::remote_attestation(ias_url, sub_key, &quote)?;
        let mrenclave_ver = enclave_context.mrenclave_ver();
        let my_roster_idx = enclave_context.read_group_key().my_roster_idx();

        Ok(output::ReturnRegisterReport::new(
            report.into_vec(),
            report_sig.into_vec(),
            mrenclave_ver,
            my_roster_idx,
        ))
    }
}
