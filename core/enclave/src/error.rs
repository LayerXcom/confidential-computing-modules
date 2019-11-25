use std::{
    prelude::v1::*,
    io,
    fmt,
};

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[derive(Debug)]
pub enum EnclaveError {
    IoError(io::Error),
    Ed25519Error(ed25519_dalek::SignatureError),
    RingError{ err: ring::error::Unspecified},
    SgxError{ err: sgx_types::sgx_status_t },
}

impl From<io::Error> for EnclaveError {
    fn from(err: io::Error) -> Self {
        EnclaveError::IoError(err)
    }
}

impl From<ed25519_dalek::SignatureError> for EnclaveError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        EnclaveError::Ed25519Error(err)
    }
}

impl From<sgx_types::sgx_status_t> for EnclaveError {
    fn from(err: sgx_types::sgx_status_t) -> Self {
        EnclaveError::SgxError{ err }
    }
}

impl From<ring::error::Unspecified> for EnclaveError {
    fn from(err: ring::error::Unspecified) -> Self {
        EnclaveError::RingError{ err }
    }
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EnclaveError::IoError(ref err) => write!(f, "I/O error: {}", err),
            EnclaveError::Ed25519Error(ref err) => write!(f, "Ed25519 error: {}", err),
            EnclaveError::SgxError{ err } => write!(f, "Sgx Error: {:?}", err),
            EnclaveError::RingError{ err } => write!(f, "Ring Error: {:?}", err),
        }
    }
}
