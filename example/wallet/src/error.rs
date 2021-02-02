use parity_crypto as crypto;
use std::io;
use thiserror::Error;

/// Alias of wallet operation result.
pub type Result<T> = std::result::Result<T, WalletError>;

/// Define Wallet errors.
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Invalid keyfile")]
    InvalidKeyfile,
    #[error("Exceeded maximum retries when deduplicating filename.")]
    OverRetries,
    #[error("Invalid path")]
    InvalidPath,
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    CryptoError(#[from] crypto::Error),
    #[error("{0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
}
