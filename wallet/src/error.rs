use parity_crypto as crypto;
use std::{error::Error, fmt, io};

/// Alias of wallet operation result.
pub type Result<T> = std::result::Result<T, WalletError>;

/// Define Wallet errors.
#[derive(Debug)]
pub enum WalletError {
    InvalidPassword,
    InvalidKeyfile,
    OverRetries,
    InvalidPath,
    IoError(io::Error),
    CryptoError(crypto::Error),
    SerdeError(serde_json::Error),
    Ed25519Error(ed25519_dalek::SignatureError),
}

impl From<io::Error> for WalletError {
    fn from(e: io::Error) -> Self {
        WalletError::IoError(e)
    }
}

impl From<crypto::Error> for WalletError {
    fn from(e: crypto::Error) -> Self {
        WalletError::CryptoError(e)
    }
}

impl From<serde_json::Error> for WalletError {
    fn from(e: serde_json::Error) -> Self {
        WalletError::SerdeError(e)
    }
}

impl From<ed25519_dalek::SignatureError> for WalletError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        WalletError::Ed25519Error(err)
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WalletError::InvalidPassword => write!(f, "Invalid password"),
            WalletError::InvalidKeyfile => write!(f, "Invalid keyfile"),
            WalletError::OverRetries => {
                write!(f, "Exceeded maximum retries when deduplicating filename.")
            }
            WalletError::InvalidPath => write!(f, "Invalid path"),
            WalletError::IoError(ref err) => write!(f, "I/O error: {}", err),
            WalletError::CryptoError(ref err) => write!(f, "crypto error: {}", err),
            WalletError::SerdeError(ref err) => write!(f, "serde error: {}", err),
            WalletError::Ed25519Error(ref err) => write!(f, "Ed25519 error: {}", err),
        }
    }
}

impl Error for WalletError {
    fn description(&self) -> &str {
        match *self {
            WalletError::InvalidPassword => "Invalid password",
            WalletError::InvalidKeyfile => "Invalid keyfile",
            WalletError::OverRetries => "Exceeded maximum retries when deduplicating filename.",
            WalletError::InvalidPath => "Invalid path",
            WalletError::IoError(ref err) => err.description(),
            WalletError::CryptoError(ref err) => err.description(),
            WalletError::SerdeError(ref err) => err.description(),
            WalletError::Ed25519Error(ref err) => "Ed25519 error:",
        }
    }
}
