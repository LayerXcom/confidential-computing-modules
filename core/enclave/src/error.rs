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
    HttpsEnclaveError(https_enclave::Error),
    HexError(hex::FromHexError),
    WebpkiError(webpki::Error),
    Base64Error(base64::DecodeError),
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

impl From<https_enclave::Error> for EnclaveError {
    fn from(err: https_enclave::Error) -> Self {
        EnclaveError::HttpsEnclaveError(err)
    }
}

impl From<hex::FromHexError> for EnclaveError {
    fn from(err: hex::FromHexError) -> Self {
        EnclaveError::HexError(err)
    }
}

impl From<webpki::Error> for EnclaveError {
    fn from(err: webpki::Error) -> Self {
        EnclaveError::WebpkiError(err)
    }
}

impl From<base64::DecodeError> for EnclaveError {
    fn from(err: base64::DecodeError) -> Self {
        EnclaveError::Base64Error(err)
    }
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EnclaveError::IoError(ref err) => write!(f, "I/O error: {}", err),
            EnclaveError::Ed25519Error(ref err) => write!(f, "Ed25519 error: {}", err),
            EnclaveError::SgxError{ err } => write!(f, "Sgx Error: {:?}", err),
            EnclaveError::RingError{ err } => write!(f, "Ring Error: {:?}", err),
            EnclaveError::HttpsEnclaveError(ref err) => write!(f, "Https enclacve error: {}", err),
            EnclaveError::HexError(ref err) => write!(f, "Hex error: {}", err),
            EnclaveError::WebpkiError(ref err) => write!(f, "Webpki error: {}", err),
            EnclaveError::Base64Error(ref err) => write!(f, "Base64 decode error: {}", err),
        }
    }
}
