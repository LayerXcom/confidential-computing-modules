use frame_sodium::SodiumPrivateKey;
#[cfg(feature = "std")]
use rand::Rng;
#[cfg(feature = "std")]
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use rand_os::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, vec::Vec};

/// A marker trait for request body
pub trait RequestBody: DeserializeOwned + Serialize + Debug + Clone {}

/// A request body to backup path secret to key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupPathSecretRequestBody {
    #[serde(with = "serde_bytes")]
    path_secret: Vec<u8>,
    epoch: u32,
    roster_idx: u32,
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
}

impl BackupPathSecretRequestBody {
    pub fn new(path_secret: Vec<u8>, epoch: u32, roster_idx: u32, id: Vec<u8>) -> Self {
        Self {
            path_secret,
            epoch,
            roster_idx,
            id,
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn path_secret(&self) -> &[u8] {
        &self.path_secret[..]
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn id(&self) -> &[u8] {
        &self.id[..]
    }
}

impl RequestBody for BackupPathSecretRequestBody {}

/// A request body to backup all path secrets to key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupAllPathSecretsRequestBody(pub Vec<BackupPathSecretRequestBody>);

impl BackupAllPathSecretsRequestBody {
    pub fn new(body: Vec<BackupPathSecretRequestBody>) -> Self {
        Self(body)
    }
}

impl RequestBody for BackupAllPathSecretsRequestBody {}

/// A Request body to recover a PathSecret specified by roster_idx and id from key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoverPathSecretRequestBody {
    roster_idx: u32,
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
}

impl RecoverPathSecretRequestBody {
    pub fn new(roster_idx: u32, id: Vec<u8>) -> Self {
        Self { roster_idx, id }
    }

    pub fn id(&self) -> &[u8] {
        &self.id[..]
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }
}

impl RequestBody for RecoverPathSecretRequestBody {}

/// A Request body to recover all PathSecrets specified by roster_idx from key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoverAllPathSecretsRequestbody {
    roster_idx: u32,
}

impl RecoverAllPathSecretsRequestbody {
    pub fn new(roster_idx: u32) -> Self {
        Self { roster_idx }
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }
}

impl RequestBody for RecoverAllPathSecretsRequestbody {}

/// A Request body to store enclave decryption key to key-vault enclave
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupEnclaveDecryptionKeyRequestBody {
    dec_key: SodiumPrivateKey,
}

impl BackupEnclaveDecryptionKeyRequestBody {
    pub fn new(dec_key: SodiumPrivateKey) -> Self {
        Self { dec_key }
    }

    pub fn dec_key(&self) -> &SodiumPrivateKey {
        &self.dec_key
    }
}

impl RequestBody for BackupEnclaveDecryptionKeyRequestBody {}

/// A Request body to recover enclave decryption key from key-vault enclave
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoverEnclaveDecryptionKeyRequestBody;

impl RequestBody for RecoverEnclaveDecryptionKeyRequestBody {}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum KeyVaultCmd {
    StorePathSecret,
    RecoverPathSecret,
    ManuallyStoreAllPathSecrets,
    ManuallyRecoverAllPathSecrets,
    StoreEnclaveDecryptionKey,
    RecoverEnclaveDecryptionKey,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyVaultRequest<B: RequestBody> {
    cmd: KeyVaultCmd,
    body: B,
}

impl<B: RequestBody> KeyVaultRequest<B> {
    pub fn new(cmd: KeyVaultCmd, body: B) -> KeyVaultRequest<B> {
        KeyVaultRequest { cmd, body }
    }
}
