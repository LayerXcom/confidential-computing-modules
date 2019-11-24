use std::{
    prelude::v1::*,
    io,
    fmt,
};

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[derive(Debug)]
pub enum EnclaveError {
    IoError(io::Error),
    Secp256k1Error(secp256k1::Error),
    RingError{ err: ring::error::Unspecified},
    SgxError{ err: sgx_types::sgx_status_t },
}

impl From<io::Error> for EnclaveError {
    fn from(err: io::Error) -> Self {
        EnclaveError::IoError(err)
    }
}

impl From<secp256k1::Error> for EnclaveError {
    fn from(err: secp256k1::Error) -> Self {
        EnclaveError::Secp256k1Error(err)
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
            EnclaveError::Secp256k1Error(ref err) => write!(f, "Secp256k1 error: {}", err),
            EnclaveError::SgxError{ err } => write!(f, "Sgx Error: {:?}", err),
            EnclaveError::RingError{ err } => write!(f, "Ring Error: {:?}", err),
        }
    }
}
