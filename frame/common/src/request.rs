use crate::localstd::vec::Vec;
use crate::serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::serde_bytes;
#[cfg(feature = "std")]
use rand::Rng;
#[cfg(feature = "std")]
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use rand_os::OsRng;

/// A Request to recover a PathSecret specified by roster_idx and id from key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "crate::serde")]
pub struct RecoverRequest {
    roster_idx: u32,
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
}

impl RecoverRequest {
    pub fn new(roster_idx: u32, id: Vec<u8>) -> Self {
        RecoverRequest { roster_idx, id }
    }

    pub fn id(&self) -> &[u8] {
        &self.id[..]
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }
}

/// A Request to recover all PathSecrets specified by roster_idx from key-vault server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "crate::serde")]
pub struct RecoverAllRequest {
    roster_idx: u32,
}

impl RecoverAllRequest {
    pub fn new(roster_idx: u32) -> Self {
        RecoverAllRequest { roster_idx }
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub enum KeyVaultCmd {
    Store,
    Recover,
    ManuallyStoreAll,
    ManuallyRecoverAll,
}

#[derive(Debug, Clone, Serialize)]
#[serde(crate = "crate::serde")]
pub struct KeyVaultRequest<DE: DeserializeOwned> {
    cmd: KeyVaultCmd,
    body: DE,
}

impl<DE: DeserializeOwned> KeyVaultRequest<DE> {
    pub fn new(cmd: KeyVaultCmd, body: DE) -> KeyVaultRequest<DE> {
        KeyVaultRequest { cmd, body }
    }
}
