use thiserror::Error;

#[derive(Error, Debug)]
pub enum MraTLSError {
    #[error("Error: {0}")]
    Error(#[from] anyhow::Error),

    #[error("rustls error: {0}")]
    RustlsError(#[from] rustls::TLSError),
}
