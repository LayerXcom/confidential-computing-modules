use crate::local_anyhow::Result;
use crate::localstd::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    string::String,
};
use crate::sealing::{SealedEnclaveDecryptionKey, UnsealedEnclaveDecryptionKey};
use frame_config::PJ_ROOT_DIR;
use serde_json_sgx as serde_json;
use tracing::info;

const DEC_KEY_FILE_NAME: &str = "enclave_decryption_key";

#[derive(Debug, Clone, Default)]
pub struct StoreEnclaveDecryptionKey {
    local_dir_path: PathBuf,
}

impl StoreEnclaveDecryptionKey {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let local_dir_path = (*PJ_ROOT_DIR).to_path_buf().join(path);
        fs::create_dir_all(&local_dir_path).expect("Failed to create the path");
        StoreEnclaveDecryptionKey { local_dir_path }
    }

    pub fn create_dir_all<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        self.local_dir_path.push(path);
        fs::create_dir_all(&self.local_dir_path)?;
        Ok(self)
    }

    pub fn local_dir_path(&self) -> &Path {
        &self.local_dir_path
    }

    pub fn save_to_local_filesystem(
        &self,
        sealed_dec_key: &SealedEnclaveDecryptionKey<'_>,
    ) -> Result<()> {
        let file_path = self.local_dir_path.join(DEC_KEY_FILE_NAME);
        info!(
            "Saving a sealed enclave decryption key to the path: {:?}",
            file_path
        );
        let mut file = fs::File::create(file_path)?;
        serde_json::to_writer(&mut file, &sealed_dec_key)?;
        file.flush()?;
        file.sync_all()?;

        Ok(())
    }

    pub fn load_from_local_filesystem(&self) -> Result<UnsealedEnclaveDecryptionKey> {
        let file_path = self.local_dir_path.join(DEC_KEY_FILE_NAME);
        info!(
            "Loading a sealed enclave decryption key from the path: {:?}",
            file_path
        );
        let mut file = fs::File::open(file_path)?;
        // `from_reader` nothing owns the data, therefore you cannot have a reference to that data in your struct.
        // using `from_str` from an owned buffer.
        // ref: https://stackoverflow.com/questions/60801133/how-do-i-use-serde-to-deserialize-structs-with-references-from-a-reader
        let mut strbuf = String::new();
        file.read_to_string(&mut strbuf)?;
        let sealed_dec_key: SealedEnclaveDecryptionKey = serde_json::from_str(&strbuf)?;

        // `sealed_dec_key` is only valid as long as `strbuf` exists.
        // so, it's unsealed here.
        sealed_dec_key.unsealing()
    }
}
