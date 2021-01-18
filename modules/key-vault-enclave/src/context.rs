use frame_config::IAS_ROOT_CERT;
use frame_config::PATH_SECRETS_DIR;
use frame_runtime::traits::*;
use frame_treekem::StorePathSecrets;
use std::{env, string::String, vec::Vec};

pub struct KeyVaultEnclaveContext {
    version: usize,
    ias_url: String,
    sub_key: String,
    key_vault_endpoint: String,
    spid: String,
    store_path_secrets: StorePathSecrets,
    ias_root_cert: Vec<u8>,
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

    fn store_path_secrets(&self) -> &StorePathSecrets {
        &self.store_path_secrets
    }

    fn ias_root_cert(&self) -> &[u8] {
        &self.ias_root_cert
    }
}

impl KeyVaultEnclaveContext {
    pub fn new(version: usize) -> Self {
        let spid = env::var("SPID").expect("SPID is not set");
        let ias_url = env::var("IAS_URL").expect("IAS_URL is not set");
        let sub_key = env::var("SUB_KEY").expect("SUB_KEY is not set");
        let key_vault_endpoint =
            env::var("KEY_VAULT_ENDPOINT").expect("KEY_VAULT_ENDPOINT is not set");
        let store_path_secrets = StorePathSecrets::new(&*PATH_SECRETS_DIR);

        Self {
            version,
            ias_url,
            sub_key,
            key_vault_endpoint,
            spid,
            store_path_secrets,
            ias_root_cert: (&*IAS_ROOT_CERT).to_vec(),
        }
    }
}
