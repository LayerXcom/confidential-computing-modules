use frame_types::UntrustedStatus;
use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, FrameEnclaveError>;

#[derive(Error, Debug)]
pub enum FrameEnclaveError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Codec error: {0:?}")]
    CodecError(codec::Error),

    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),

    #[error("Sgx Error: {err:?}")]
    SgxError { err: sgx_types::sgx_status_t },

    #[error("Enclave ocall failed function: {function:?}, status: {status:?}")]
    UntrustedError {
        status: UntrustedStatus,
        function: &'static str,
    },

    #[error("Policy violation")]
    PolicyError,
}
