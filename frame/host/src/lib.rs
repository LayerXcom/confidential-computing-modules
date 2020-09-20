#[macro_use]
extern crate lazy_static;

mod config;
pub mod ecalls;
pub mod engine;
mod error;
pub mod init_enclave;
mod ocalls;
mod store_path_secrets;

pub use error::FrameHostError as Error;
pub use init_enclave::EnclaveDir;
use std::{env, path::PathBuf};
pub use store_path_secrets::StorePathSecrets;

lazy_static! {
    pub static ref PJ_ROOT_DIR: PathBuf = {
        let pj_root_dir = env::var("PJ_ROOT_DIR").unwrap_or_else(|_| {
            format!(
                "{}/anonify",
                dirs::home_dir().unwrap().into_os_string().to_str().unwrap()
            )
        });
        PathBuf::from(pj_root_dir)
    };
}
