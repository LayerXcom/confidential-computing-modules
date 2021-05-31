use anyhow::anyhow;
use frame_config::IAS_ROOT_CERT;
use remote_attestation::{AttestedReport, EncodedQuote, QuoteTarget};
use sgx_types::sgx_report_data_t;
use std::env;

#[derive(Clone, Debug)]
pub struct OcclumEnclaveContext {
    ias_url: String,
    spid: String,
    sub_key: String,
}

impl OcclumEnclaveContext {
    pub fn new() -> Self {
        let ias_url = env::var("IAS_URL").expect("IAS_URL is not set");
        let sub_key = env::var("SUB_KEY").expect("SUB_KEY is not set");
        assert!(!sub_key.is_empty(), "SUB_KEY shouldn't be empty");
        let spid = env::var("SPID").expect("SPID is not set");
        assert!(!spid.is_empty(), "SPID shouldn't be empty");

        Self {
            spid,
            sub_key,
            ias_url,
        }
    }

    pub fn do_remote_attestation(&self) -> anyhow::Result<AttestedReport> {
        self.quote()?
            .remote_attestation(&self.ias_url, &self.sub_key, IAS_ROOT_CERT.to_vec())
            .map_err(Into::into)
    }

    // TODO: impl QuoteGetter
    fn quote(&self) -> anyhow::Result<EncodedQuote> {
        let report_data = sgx_report_data_t::default();
        QuoteTarget::new()?
            .set_enclave_report(&report_data)?
            .create_quote(&self.spid)
            .map_err(|e| anyhow!("{:?}", e))
    }
}
