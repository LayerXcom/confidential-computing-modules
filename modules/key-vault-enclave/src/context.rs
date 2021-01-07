use std::string::String;
use frame_runtime::traits::*;
use crate::error::Result;

pub struct KeyVaultEnclaveContext {
    version: usize,
    ias_url: String,
    sub_key: String,
    server_address: String,
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

    fn server_address(&self) -> &str {
        &self.server_address
    }

    fn spid(&self) -> &str {
        &self.spid
    }
}

impl KeyVaultEnclaveContext {
    pub fn new(spid: String) -> Result<Self> {
        unimplemented!();
    }
}
