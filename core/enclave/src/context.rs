use sgx_types::*;
use std::prelude::v1::*;
use sgx_tse::rsgx_create_report;
use anonify_common::{LockParam, kvs::{MemoryDB, DBValue}, UserAddress};
use anonify_app_preluder::{mem_name_to_id, Ciphertext};
use anonify_runtime::{State, StateGetter, StateType, MemId};
use crate::{
    crypto::{Eik, SymmetricKey},
    attestation::TEST_SPID,
    ocalls::{sgx_init_quote, get_quote},
    error::Result,
    kvs::{EnclaveDB, EnclaveDBTx},
    state::{Current, UserState, StateValue},
};

lazy_static! {
    pub static ref ENCLAVE_CONTEXT: EnclaveContext<StateType>
        = EnclaveContext::new(TEST_SPID).unwrap();
}

impl StateGetter for EnclaveContext<StateType> {
    fn get<S: State>(&self, key: &UserAddress, name: &str) -> anyhow::Result<S> {
        let mem_id = mem_name_to_id(name);
        let mut buf = self.db.get(key, &mem_id).into_inner_state().into_bytes();
        if buf.len() == 0 {
            return Ok(Default::default());
        }

        S::from_bytes(&mut buf)
    }

    fn get_by_id(&self, key: &UserAddress, mem_id: MemId) -> StateType {
        self.db.get(key, &mem_id).into_inner_state()
    }
}

/// spid: Service procider ID for the ISV.
#[derive(Clone)]
pub struct EnclaveContext<S: State> {
    spid: sgx_spid_t,
    identity_key: Eik,
    db: EnclaveDB<S>,
}

// TODO: Consider SGX_ERROR_BUSY.
impl EnclaveContext<StateType> {
    pub fn new(spid: &str) -> Result<Self> {
        let spid_vec = hex::decode(spid)?;
        let mut id = [0; 16];
        id.copy_from_slice(&spid_vec);
        let spid: sgx_spid_t = sgx_spid_t { id };

        let identity_key = Eik::new()?;
        let db = EnclaveDB::new();

        Ok(EnclaveContext{
            spid,
            identity_key,
            db,
        })
    }

    /// Generate Base64-encoded QUOTE data structure.
    /// QUOTE will be sent to Attestation Serivce to verify SGX's status.
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
    /// This signature is used to verify enclacve's program dependencies and
    /// should be verified in the public available place such as smart contracr on blokchain.
    pub fn sign(&self, msg: &LockParam) -> Result<secp256k1::Signature> {
        self.identity_key.sign(msg.as_bytes())
    }

    // Only State with `Current` allows to access to the database to avoid from
    // storing data which have not been considered globally consensused.
    pub fn write_cipheriv(
        &self,
        cipheriv: Ciphertext,
        symm_key: &SymmetricKey
    ) -> Result<()> {
        let user_state = UserState::<StateType, Current>::decrypt(cipheriv, &symm_key)?;
        let address = user_state.address();
        let mem_id = user_state.mem_id();
        let sv = user_state.into_sv();

        self.db.write(address, mem_id, sv);

        Ok(())
    }

    /// Get the user's state value for the specified memory id.
    pub fn state_value(&self, key: &UserAddress, mem_id: &MemId) -> StateValue<StateType, Current> {
        self.db.get(key, &mem_id)
    }

    /// Return Attestation report
    fn report(&self, target_info: &sgx_target_info_t) -> Result<sgx_report_t> {
        let mut report = sgx_report_t::default();
        let report_data = &self.identity_key.report_date()?;

        if let Ok(r) = rsgx_create_report(&target_info, &report_data) {
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
