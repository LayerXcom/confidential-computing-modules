use frame_types::UntrustedStatus;
use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, FrameRAError>;

#[derive(Error, Debug)]
pub enum FrameRAError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),

    #[error("Sgx Error: {err:?}")]
    SgxError { err: sgx_types::sgx_status_t },

    #[error("Enclave ocall failed function: {function:?}, status: {status:?}")]
    UntrustedError {
        status: UntrustedStatus,
        function: &'static str,
    },
}
