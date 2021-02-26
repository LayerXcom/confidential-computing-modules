use anyhow::anyhow;
use frame_common::crypto::ExportPathSecret;
use frame_mra_tls::{
    key_vault::{
        request::{
            BackupAllPathSecretsRequestBody, BackupEnclaveDecryptionKeyRequestBody,
            BackupPathSecretRequestBody, RecoverAllPathSecretsRequestbody,
            RecoverEnclaveDecryptionKeyRequestBody, RecoverPathSecretRequestBody,
        },
        response::RecoveredPathSecret,
    },
    RequestHandler,
};
use frame_treekem::{PathSecret, StorePathSecrets};
use serde_json::Value;
use std::{string::ToString, vec::Vec};

#[derive(Default, Clone)]
pub struct KeyVaultHandler {
    store_path_secrets: StorePathSecrets,
}

impl RequestHandler for KeyVaultHandler {
    fn handle_json(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded: Value = serde_json::from_slice(&msg)?;
        let cmd = decoded["cmd"]
            .as_str()
            .ok_or_else(|| anyhow!("msg doesn't contain cmd"))?;

        match cmd {
            "StorePathSecret" => self.store_path_secret(decoded["body"].clone()),
            "RecoverPathSecret" => self.recover_path_secret(decoded["body"].clone()),
            "ManuallyStoreAllPathSecrets" => {
                self.manually_store_path_secrets_all(decoded["body"].clone())
            }
            "ManuallyRecoverAllPathSecrets" => {
                self.manually_recover_path_secrets_all(decoded["body"].clone())
            }
            "StoreEnclaveDecryptionKey" => unimplemented!(),
            "RecoverEnclaveDecrptionKey" => unimplemented!(),
            _ => unreachable!("got unknown command: {:?}", cmd),
        }
    }
}

impl KeyVaultHandler {
    pub fn new(store_path_secrets: StorePathSecrets) -> Self {
        Self { store_path_secrets }
    }

    fn store_enclave_decryption_key(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let backup_path_secret: BackupEnclaveDecryptionKeyRequestBody = serde_json::from_value(body)?;
        
        let eps = PathSecret::from(backup_path_secret.path_secret())
            .try_into_exporting(backup_path_secret.epoch(), backup_path_secret.id())?;
        self.store_path_secrets
            .clone()
            .create_dir_all(backup_path_secret.roster_idx().to_string())?
            .save_to_local_filesystem(&eps)?;

        serde_json::to_vec(&eps).map_err(Into::into)
    }

    fn store_path_secret(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let backup_path_secret: BackupPathSecretRequestBody = serde_json::from_value(body)?;
        let eps = PathSecret::from(backup_path_secret.path_secret())
            .try_into_exporting(backup_path_secret.epoch(), backup_path_secret.id())?;
        self.store_path_secrets
            .clone()
            .create_dir_all(backup_path_secret.roster_idx().to_string())?
            .save_to_local_filesystem(&eps)?;

        serde_json::to_vec(&eps).map_err(Into::into)
    }

    fn recover_path_secret(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let recover_path_secret: RecoverPathSecretRequestBody = serde_json::from_value(body)?;
        let ps_id = recover_path_secret.id();
        let eps = self
            .store_path_secrets
            .clone()
            .create_dir_all(recover_path_secret.roster_idx().to_string())?
            .load_from_local_filesystem(ps_id)?;
        let path_secret = PathSecret::try_from_importing(eps.clone())?;
        let rps =
            RecoveredPathSecret::new(path_secret.as_bytes().to_vec(), eps.epoch(), ps_id.to_vec());

        serde_json::to_vec(&rps).map_err(Into::into)
    }

    fn manually_store_path_secrets_all(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let mut epss: Vec<ExportPathSecret> = vec![];
        let backup_path_secrets: BackupAllPathSecretsRequestBody = serde_json::from_value(body)?;

        for backup_path_secret in backup_path_secrets.0 {
            let eps = PathSecret::from(backup_path_secret.path_secret())
                .try_into_exporting(backup_path_secret.epoch(), backup_path_secret.id())?;
            let store_path_secrets = self
                .store_path_secrets
                .clone()
                .create_dir_all(backup_path_secret.roster_idx().to_string())?;
            store_path_secrets.save_to_local_filesystem(&eps)?;
            epss.push(eps);
        }

        serde_json::to_vec(&epss).map_err(Into::into)
    }

    fn manually_recover_path_secrets_all(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let mut recovered_path_secrets: Vec<RecoveredPathSecret> = vec![];

        let recover_path_secret: RecoverAllPathSecretsRequestbody = serde_json::from_value(body)?;
        let store_path_secrets = self
            .store_path_secrets
            .clone()
            .create_dir_all(recover_path_secret.roster_idx().to_string())?;
        let ps_ids = store_path_secrets.get_all_path_secret_ids()?;

        for ps_id in ps_ids {
            let eps = store_path_secrets.load_from_local_filesystem(&ps_id)?;
            let ps = PathSecret::try_from_importing(eps.clone())?;
            let rps = RecoveredPathSecret::new(ps.as_bytes().to_vec(), eps.epoch(), ps_id);
            recovered_path_secrets.push(rps);
        }

        serde_json::to_vec(&recovered_path_secrets).map_err(Into::into)
    }
}
