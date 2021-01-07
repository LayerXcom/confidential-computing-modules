use anonify_config::KEY_VAULT_MRENCLAVE_VERSION;
use frame_runtime::traits::*;
use std::{env, string::String};

pub struct KeyVaultEnclaveContext {
    version: usize,
    ias_url: String,
    sub_key: String,
    key_vault_endpoint: String,
    spid: String,
}

impl ConfigGetter for KeyVaultEnclaveContext {
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
}

impl KeyVaultEnclaveContext {
    pub fn new() -> Self {
        let spid = env::var("SPID").expect("SPID is not set");
        let ias_url = env::var("IAS_URL").expect("IAS_URL is not set");
        let sub_key = env::var("SUB_KEY").expect("SUB_KEY is not set");
        let key_vault_endpoint =
            env::var("KEY_VAULT_ENDPOINT").expect("KEY_VAULT_ENDPOINT is not set");

        Self {
            version: KEY_VAULT_MRENCLAVE_VERSION,
            ias_url,
            sub_key,
            key_vault_endpoint,
            spid,
        }
    }
}
