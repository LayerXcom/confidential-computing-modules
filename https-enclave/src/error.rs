use std::{
    prelude::v1::*,
    io,
    fmt,
};

pub type Result<T> = std::result::Result<T, HttpsEnclaveError>;

#[derive(Debug)]
pub enum HttpsEnclaveError {
    IoError(io::Error),
    SgxError{ err: sgx_types::sgx_status_t },
    WebpkiError(webpki::InvalidDNSNameError),
}

impl From<io::Error> for HttpsEnclaveError {
    fn from(err: io::Error) -> Self {
        HttpsEnclaveError::IoError(err)
    }
}

impl From<sgx_types::sgx_status_t> for HttpsEnclaveError {
    fn from(err: sgx_types::sgx_status_t) -> Self {
        HttpsEnclaveError::SgxError{ err }
    }
}

impl From<webpki::InvalidDNSNameError> for HttpsEnclaveError {
    fn from(err: webpki::InvalidDNSNameError) -> Self {
        HttpsEnclaveError::WebpkiError(err)
    }
}

impl fmt::Display for HttpsEnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HttpsEnclaveError::IoError(ref err) => write!(f, "I/O error: {}", err),
            HttpsEnclaveError::SgxError{ err } => write!(f, "Sgx Error: {:?}", err),
            HttpsEnclaveError::WebpkiError(ref err) => write!(f, "Webpki error: {}", err),
        }
    }
}
