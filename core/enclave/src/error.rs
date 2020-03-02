use std::{
    io,
    fmt,
    error::Error,
};
// use thiserror::Error;

pub type Result<T> = std::result::Result<T, EnclaveError>;

// #[derive(Error, Debug)]
// pub enum EnclaveError {
//     #[error("Error: {0}")]
//     Error(#[from] anyhow::Error),
//     #[error("IO error: {0}")]
//     IoError(#[from] io::Error),
//     #[error("SGX ocall failed function: {function:?}, status: {status:?}")]
//     Sgx {
//         status: sgx_status_t,
//         function: &'static str,
//     },
// }

#[derive(Debug)]
pub enum EnclaveError {
    IoError(io::Error),
    Ed25519Error(ed25519_dalek::SignatureError),
    RingError{ err: ring::error::Unspecified},
    SgxError{ err: sgx_types::sgx_status_t },
    HttpsEnclaveError(anonify_attestation::Error),
    HexError(hex::FromHexError),
    WebpkiError(webpki::Error),
    Base64Error(base64::DecodeError),
    Secp256k1Error(secp256k1::Error),
    CodecError(codec::Error),
    AnyhowError(anyhow::Error),
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

impl From<anonify_attestation::Error> for EnclaveError {
    fn from(err: anonify_attestation::Error) -> Self {
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

impl From<secp256k1::Error> for EnclaveError {
    fn from(err: secp256k1::Error) -> Self {
        EnclaveError::Secp256k1Error(err)
    }
}

impl From<codec::Error> for EnclaveError {
    fn from(err: codec::Error) -> Self {
        EnclaveError::CodecError(err)
    }
}

impl From<anyhow::Error> for EnclaveError {
    fn from(err: anyhow::Error) -> Self {
        EnclaveError::AnyhowError(err)
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
            EnclaveError::Secp256k1Error(ref err) => write!(f, "Secp256k1 error"),
            EnclaveError::CodecError(ref err) => write!(f, "Codec error"),
            EnclaveError::AnyhowError(ref err) => write!(f, "Anyhow error"),
        }
    }
}

impl Error for EnclaveError { }
