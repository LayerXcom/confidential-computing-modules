use anyhow::anyhow;
use frame_common::crypto::{BackupCmd, BackupPathSecret, RecoverPathSecret};
use frame_mra_tls::RequestHandler;
use frame_treekem::{PathSecret, StorePathSecrets};
use serde_json::Value;

use std::vec::Vec;

#[derive(Default, Clone)]
pub struct BackupHandler;

impl RequestHandler for BackupHandler {
    fn handle_json(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded: Value = serde_json::from_slice(&msg)?;
        let cmd = decoded["cmd"]
            .as_u64()
            .ok_or_else(|| anyhow!("msg doesn't contain cmd"))?;

        match BackupCmd::from(cmd) {
            BackupCmd::STORE => store_path_secret(decoded["body"].clone()),
            BackupCmd::RECOVER => recover_path_secret(decoded["body"].clone()),
        }
    }
}

fn store_path_secret(body: Value) -> anyhow::Result<Vec<u8>> {
    let backup_path_secret: BackupPathSecret = serde_json::from_value(body)?;
    let path_secret = PathSecret::from(backup_path_secret.path_secret());
    let roster_idx = backup_path_secret.roster_idx();
    let epoch = backup_path_secret.epoch();
    let id = backup_path_secret.id();

    let eps = path_secret.try_into_exporting(epoch, &id)?;
    let store_path_secrets = StorePathSecrets::new(format!(".anonify/pathsecrets/{}", roster_idx));
    store_path_secrets.save_to_local_filesystem(&eps)?;

    serde_json::to_vec(&eps).map_err(Into::into)
}

fn recover_path_secret(body: Value) -> anyhow::Result<Vec<u8>> {
    let recover_path_secret: RecoverPathSecret = serde_json::from_value(body)?;
    let roster_idx = recover_path_secret.roster_idx();
    let id = recover_path_secret.id();

    let store_path_secrets = StorePathSecrets::new(format!(".anonify/pathsecrets/{}", roster_idx));
    let eps = store_path_secrets.load_from_local_filesystem(id)?;
    let path_secret = PathSecret::try_from_importing(eps)?;

    serde_json::to_vec(path_secret.as_bytes()).map_err(Into::into)
}
