use frame_types::UntrustedStatus;
use std::{io, string::String, vec::Vec};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, FrameRAError>;

#[derive(Error, Debug)]
pub enum FrameRAError {
    #[error("Parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
    #[error("base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("serde json error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("web pki error: {0}")]
    WebpkiJsonError(#[from] webpki::Error),
    #[error("http req error: {0}")]
    HttpReqError(#[from] http_req::error::Error),

    #[error("Ocall Error: function: {function:?}, status: {status:?}")]
    OcallError {
        status: sgx_types::sgx_status_t,
        function: &'static str,
    },
    #[error("Error caused in untrusted part: function: {function:?}, status: {status:?}")]
    UntrustedError {
        status: UntrustedStatus,
        function: &'static str,
    },

    #[error("The status code indicates that it's not Successful, response: {0:?}")]
    StatusCodeError(http_req::response::Response),
    #[error("The Remote Attestation API version ({0}) is not supported")]
    ApiVersionError(u64),
    #[error("Invalid Enclave Quote Status: {0}")]
    QuoteStatusError(String),
    #[error("Failed to fetch isvEnclaveQuoteStatus from attestation report")]
    NotFoundisvEnclaveQuoteStatusError,
    #[error("Certificate is blank")]
    BlankCertError,
    #[error("qe_report is not valid: {0}")]
    VerifyReportError(sgx_types::sgx_status_t),
    #[error("received quote is modified or replayed: report.data[..32]: {rhs:?}, SHA256(p_nonce||p_quote): {lhs:?}")]
    VerifyQuoteError { rhs: Vec<u8>, lhs: Vec<u8> },
    #[error("{0}")]
    Others(sgx_types::sgx_status_t),
}
