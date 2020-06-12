use std::{
    sync::{SgxRwLock, Arc},
    env,
};
use sgx_types::*;
use std::prelude::v1::*;
use anonify_common::{kvs::{MemoryDB, DBValue}, UserAddress};
use anonify_app_preluder::{mem_name_to_id, Ciphertext};
use anonify_runtime::{State, StateGetter, StateType, MemId};
use anonify_treekem::{
    handshake::{PathSecretRequest, PathSecretKVS},
    init_path_secret_kvs,
};
use codec::Encode;
use crate::{
    notify::Notifier,
    crypto::EnclaveIdentityKey,
    group_key::GroupKey,
    config::{TEST_SPID, MY_ROSTER_IDX, MAX_ROSTER_IDX, UNTIL_ROSTER_IDX, UNTIL_EPOCH},
    ocalls::{sgx_init_quote, get_quote},
    error::Result,
    kvs::{EnclaveDB, EnclaveDBTx},
    instructions::Instructions,
};

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext<StateType>
        = EnclaveContext::new(TEST_SPID).unwrap();
}

impl StateGetter for EnclaveContext<StateType> {
    fn get<S: State>(&self, key: impl Into<UserAddress>, name: &str) -> anyhow::Result<S> {
        let mem_id = mem_name_to_id(name);
        let mut buf = self.db
            .get(key.into(), mem_id)
            .into_bytes();
        if buf.len() == 0 {
            return Ok(Default::default());
        }

        S::from_bytes(&mut buf)
    }

    fn get_by_id(&self, key: UserAddress, mem_id: MemId) -> StateType {
        self.db.get(key, mem_id)
    }
}

/// spid: Service provider ID for the ISV.
#[derive(Clone)]
pub struct EnclaveContext<S: State> {
    spid: sgx_spid_t,
    identity_key: EnclaveIdentityKey,
    db: EnclaveDB<S>,
    notifier: Notifier,
    pub group_key: Arc<SgxRwLock<GroupKey>>,
}

// TODO: Consider SGX_ERROR_BUSY.
impl EnclaveContext<StateType> {
    pub fn new(spid: &str) -> Result<Self> {
        let spid_vec = hex::decode(spid)?;
        let mut id = [0; 16];
        id.copy_from_slice(&spid_vec);
        let spid: sgx_spid_t = sgx_spid_t { id };

        let identity_key = EnclaveIdentityKey::new()?;
        let db = EnclaveDB::new();

        // temporary path secrets are generated in local.
        let mut kvs = PathSecretKVS::new();
        init_path_secret_kvs(&mut kvs, UNTIL_ROSTER_IDX, UNTIL_EPOCH);
        let req = PathSecretRequest::Local(kvs);

        let my_roster_idx: usize = env::var("MY_ROSTER_IDX")
            .expect("MY_ROSTER_IDX is not set")
            .parse()
            .expect("Failed to parse MY_ROSTER_IDX to usize");
        let max_roster_idx: usize = env::var("MAX_ROSTER_IDX")
            .expect("MAX_ROSTER_IDX is not set")
            .parse()
            .expect("Failed to parse MAX_ROSTER_IDX to usize");

        let group_key = Arc::new(SgxRwLock::new(GroupKey::new(my_roster_idx, max_roster_idx, req)?));
        let notifier = Notifier::new();

        Ok(EnclaveContext{
            spid,
            identity_key,
            db,
            notifier,
            group_key,
        })
    }

    pub fn set_notification(&self, address: UserAddress) -> bool {
        self.notifier.register(address)
    }

    pub fn is_notified(&self, address: &UserAddress) -> bool {
        self.notifier.contains(&address)
    }

    /// Generate Base64-encoded QUOTE data structure.
    /// QUOTE will be sent to Attestation Service to verify SGX's status.
    /// For more information: https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
    pub fn quote(&self) -> Result<String> {
        let target_info = self.init_quote()?;
        let report = self.report(&target_info)?;
        self.encoded_quote(report)
    }

    pub(crate) fn init_quote(&self) -> Result<sgx_target_info_t> {
        let target_info = sgx_init_quote()?;
        Ok(target_info)
    }

    /// Generate a signature using enclave's identity key.
    /// This signature is used to verify enclave's program dependencies and
    /// should be verified in the public available place such as smart contract on blockchain.
    pub fn sign(&self, msg: &[u8]) -> Result<secp256k1::Signature> {
        self.identity_key.sign(msg)
    }

    pub fn update_state(
        &self,
        ciphertext: &Ciphertext,
        group_key: &mut GroupKey,
    ) -> Result<()> {
        if let Some(instructions) = Instructions::decrypt(ciphertext, group_key)? {
            let updated_states = instructions.state_transition::<StateType>(self)?;
            for state in updated_states {
                self.is_notified(&state.address);
                self.db.insert_by_updated_state(state);
            }
        }

        Ok(())
    }

    // /// Only State with `Current` allows to access to the database to avoid from
    // /// storing data which have not been considered globally consensused.
    // /// Only if the enclave join the group, you can receive ciphertext and decrypt it,
    // /// otherwise do nothing.
    // pub fn write_cipheriv(
    //     &self,
    //     cipheriv: &Ciphertext,
    //     group_key: &mut GroupKey,
    // ) -> Result<()> {
    //     if let Some(user_state) = UserState::<StateType, Current>::decrypt(cipheriv, group_key)? {
    //         let address = user_state.address();
    //         self.db.insert(address, user_state.mem_id(), user_state.into_sv());
    //         self.is_notified(&address);
    //     }

    //     Ok(())
    // }

    // /// Get the user's state value for the specified memory id.
    // pub fn state_value(&self, key: UserAddress, mem_id: MemId) -> StateValue<StateType, Current> {
    //     self.db.get(key, mem_id)
    // }

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
