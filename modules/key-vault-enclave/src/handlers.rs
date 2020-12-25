use frame_common::crypto::BackupPathSecret;
use frame_mra_tls::RequestHandler;

use std::vec::Vec;

#[derive(Default, Clone)]
pub struct BackupHandler;

impl RequestHandler for BackupHandler {
    fn handle_json(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let backup_path_secret: BackupPathSecret = serde_json::from_slice(&msg)?;
        serde_json::to_vec(&backup_path_secret).map_err(Into::into)
    }
}
