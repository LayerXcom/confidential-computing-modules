use std::{
    prelude::v1::*,
    io,
    fmt,
};

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[derive(Debug)]
pub enum EnclaveError {
    IoError(io::Error),
}

impl From<io::Error> for EnclaveError {
    fn from(e: io::Error) -> Self {
        EnclaveError::IoError(e)
    }
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EnclaveError::IoError(ref err) => write!(f, "I/O error: {}", err),
        }
    }
}
