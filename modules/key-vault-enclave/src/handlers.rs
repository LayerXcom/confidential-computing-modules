use anonify_config::PJ_ROOT_DIR;
use anyhow::anyhow;
use frame_common::crypto::{
    BackupPathSecret, ExportPathSecret, RecoverAllRequest, RecoverRequest, RecoveredPathSecret,
};
use frame_mra_tls::RequestHandler;
use frame_treekem::{PathSecret, StorePathSecrets};
use serde_json::Value;
use std::{
    fs,
    io::BufReader,
    path::{Path, PathBuf},
    string::ToString,
    vec::Vec,
};

#[derive(Default, Clone)]
pub struct KeyVaultHandler {
    store_path_secrets: StorePathSecrets,
}

impl KeyVaultHandler {
    pub fn new(store_path_secrets: StorePathSecrets) -> Self {
        Self { store_path_secrets }
    }

    fn store_path_secret(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let backup_path_secret: BackupPathSecret = serde_json::from_value(body)?;
        let eps = PathSecret::from(backup_path_secret.path_secret())
            .try_into_exporting(backup_path_secret.epoch(), backup_path_secret.id())?;
        self.store_path_secrets
            .clone()
            .push(backup_path_secret.roster_idx().to_string())
            .save_to_local_filesystem(&eps)?;

        serde_json::to_vec(&eps).map_err(Into::into)
    }

    fn recover_path_secret(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let recover_path_secret: RecoverRequest = serde_json::from_value(body)?;
        let ps_id = recover_path_secret.id();
        let eps = self
            .store_path_secrets
            .clone()
            .push(recover_path_secret.roster_idx().to_string())
            .load_from_local_filesystem(ps_id)?;
        let path_secret = PathSecret::try_from_importing(eps.clone())?;
        let rps =
            RecoveredPathSecret::new(path_secret.as_bytes().to_vec(), eps.epoch(), ps_id.to_vec());

        serde_json::to_vec(&rps).map_err(Into::into)
    }

    fn manually_store_path_secrets_all(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let mut epss: Vec<ExportPathSecret> = vec![];
        let backup_path_secrets: Vec<BackupPathSecret> = serde_json::from_value(body)?;

        for backup_path_secret in backup_path_secrets {
            let eps = PathSecret::from(backup_path_secret.path_secret())
                .try_into_exporting(backup_path_secret.epoch(), backup_path_secret.id())?;
            let store_path_secrets = self
                .store_path_secrets
                .clone()
                .push(backup_path_secret.roster_idx().to_string());
            store_path_secrets.save_to_local_filesystem(&eps)?;
            epss.push(eps);
        }

        serde_json::to_vec(&epss).map_err(Into::into)
    }

    fn manually_recover_path_secrets_all(&self, body: Value) -> anyhow::Result<Vec<u8>> {
        let mut recovered_path_secrets: Vec<RecoveredPathSecret> = vec![];

        let recover_path_secret: RecoverAllRequest = serde_json::from_value(body)?;
        let store_path_secrets = self
            .store_path_secrets
            .clone()
            .push(recover_path_secret.roster_idx().to_string());
        let ps_ids = get_local_path_secret_ids(self.store_path_secrets.local_dir_path())?;

        for ps_id in ps_ids {
            let eps = store_path_secrets.load_from_local_filesystem(&ps_id)?;
            let ps = PathSecret::try_from_importing(eps.clone())?;
            let rps = RecoveredPathSecret::new(ps.as_bytes().to_vec(), eps.epoch(), ps_id);
            recovered_path_secrets.push(rps);
        }

        serde_json::to_vec(&recovered_path_secrets).map_err(Into::into)
    }
}

impl RequestHandler for KeyVaultHandler {
    fn handle_json(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded: Value = serde_json::from_slice(&msg)?;
        let cmd = decoded["cmd"]
            .as_str()
            .ok_or_else(|| anyhow!("msg doesn't contain cmd"))?;

        match cmd {
            "Store" => self.store_path_secret(decoded["body"].clone()),
            "Recover" => self.recover_path_secret(decoded["body"].clone()),
            "ManuallyStoreAll" => self.manually_store_path_secrets_all(decoded["body"].clone()),
            "ManuallyRecoverAll" => self.manually_recover_path_secrets_all(decoded["body"].clone()),
            _ => unreachable!("got unknown command: {:?}", cmd),
        }
    }
}

pub fn get_local_path_secret_ids<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<Vec<u8>>> {
    let local_path_secret_dir_path = (*PJ_ROOT_DIR).to_path_buf().join(path);

    let file_paths: Vec<PathBuf> = fs::read_dir(local_path_secret_dir_path)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();

    let mut ids = vec![];
    for path in file_paths {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let eps: ExportPathSecret = serde_json::from_reader(reader)?;
        ids.push(eps.id_as_ref().to_vec());
    }

    Ok(ids)
}
