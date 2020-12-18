use thiserror::Error;
use std::io;

pub type Result<T> = std::result::Result<T, MraTLSError>;

#[derive(Error, Debug)]
pub enum MraTLSError {
    #[error("rustls error: {0}")]
    RustlsError(#[from] rustls::TLSError),

    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("{0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
}
