use std::{
    prelude::v1::*,
    io,
    fmt,
};

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[derive(Debug)]
pub enum EnclaveError {
    IoError(io::Error),
    SgxError{ err: sgx_types::sgx_status_t },
}

impl From<io::Error> for EnclaveError {
    fn from(err: io::Error) -> Self {
        EnclaveError::IoError(err)
    }
}

impl From<sgx_types::sgx_status_t> for EnclaveError {
    fn from(err: sgx_types::sgx_status_t) -> Self {
        EnclaveError::SgxError{ err }
    }
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EnclaveError::IoError(ref err) => write!(f, "I/O error: {}", err),
            EnclaveError::SgxError{ err } => write!(f, "Sgx Error: {:?}", err),
        }
    }
}
