use std::fs;
use frame_common::crypto::ExportPathSecret;
use frame_host::PJ_ROOT_DIR;
use failure::Error;

const PATH_SECRETS_DIR: &str = "path-secrets";

pub struct StorePathSecrets {
    local_path: PathBuf,
}

impl StorePathSecrets {
    pub fn new() -> Self {
        StorePathSecret {
            local_path: *PJ_ROOT_DIR,
        }
    }

    pub fn save_to_local_filesystem(self, eps: &ExportPathSecret) -> Result<(), Error> {
        let path = self.local_path.join(PATH_SECRETS_DIR);
        let mut file = Self::create_new_file(path)?;
        serde_json::to_writer(&mut file, &pes)?;
        file.flush()?;
        file.sync_all()?;

        Ok(())
    }

    #[cfg(unix)]
    fn create_new_file(path: &Path) -> Result<fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o660) // Owner's read & write permission
            .open(path)?;

        Ok(file)
    }

    #[cfg(not(unix))]
    fn create_new_file(path: &Path) -> Result<fs::File> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;

        Ok(file)
    }
}