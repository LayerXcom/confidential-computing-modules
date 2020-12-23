use thiserror::Error;

pub type Result<T> = std::result::Result<T, MraTLSError>;

#[derive(Error, Debug)]
pub enum MraTLSError {
    #[error("Error: {0}")]
    Error(#[from] anyhow::Error),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("rustls error: {0}")]
    RustlsError(#[from] rustls::TLSError),
    #[error("ASN.1 error: {0}")]
    ASN1Error(#[from] yasna::ASN1Error),
    #[error("{0}")]
    RAError(#[from] remote_attestation::Error),
    #[error("{0}")]
    SerdeJsonError(#[from] serde_json::Error),
}
