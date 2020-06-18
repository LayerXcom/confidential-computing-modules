use dirs;
use std::path::PathBuf;

const APPLICATION_DIRECTORY_NAME: &'static str = "anonify";

/// root directory configuration
pub(crate) fn get_default_root_dir() -> PathBuf {
    match dirs::data_local_dir() {
        Some(dir) => dir.join(APPLICATION_DIRECTORY_NAME),
        None => panic!("Undefined the local data directory."),
    }
}
