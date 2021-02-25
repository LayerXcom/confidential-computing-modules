use anyhow::Result;
use frame_common::crypto::ExportPathSecret;
use frame_config::PJ_ROOT_DIR;
use std::{
    fs,
    io::{BufReader, Write},
    path::{Path, PathBuf},
    vec::Vec,
};
use tracing::info;

/// Store exported secret_paths in the local filesystems
/// For anonify node, it is saved in the following location.
///  - PJ_ROOT_DIR/.anonify/pathsecrets/
/// For key-vault node, it is saved in the following location.
/// - PJ_ROOT_DIR/.anonify/pathsecrets/${roster_idx}/
#[derive(Debug, Clone, Default)]
pub struct StorePathSecrets {
    local_dir_path: PathBuf,
}

impl StorePathSecrets {
    pub fn new<P: AsRef<Path>>(path_secrets_dir: P) -> Self {
        let local_dir_path = (*PJ_ROOT_DIR).to_path_buf().join(path_secrets_dir);
        fs::create_dir_all(&local_dir_path).expect("Failed to create PATH_SECRETS_DIR");
        StorePathSecrets { local_dir_path }
    }

    pub fn create_dir_all<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        self.local_dir_path.push(path);
        fs::create_dir_all(&self.local_dir_path)?;
        Ok(self)
    }

    pub fn local_dir_path(&self) -> &Path {
        &self.local_dir_path
    }

    pub fn save_to_local_filesystem(&self, eps: &ExportPathSecret) -> Result<()> {
        let file_name = hex::encode(&eps.id_as_ref());
        let file_path = self.local_dir_path.join(file_name);
        info!("Saving a sealed path secret to the path: {:?}", file_path);
        let mut file = fs::File::create(file_path)?;
        serde_json::to_writer(&mut file, &eps)?;
        file.flush()?;
        file.sync_all()?;

        Ok(())
    }

    pub fn load_from_local_filesystem(&self, id: &[u8]) -> Result<ExportPathSecret> {
        let file_name = hex::encode(&id);
        let file_path = self.local_dir_path.join(file_name);
        info!(
            "Loading a sealed path secret from the path: {:?}",
            file_path
        );
        let file = fs::File::open(file_path)?;
        let reader = BufReader::new(file);
        let eps = serde_json::from_reader(reader)?;

        Ok(eps)
    }

    pub fn get_all_path_secret_ids(&self) -> Result<Vec<Vec<u8>>> {
        let file_paths: Vec<PathBuf> = fs::read_dir(&self.local_dir_path)?
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
}
