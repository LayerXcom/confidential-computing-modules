use crate::{
    anyhow, base64, http_req,
    localstd::{
        error::Error,
        fmt::{self, Display},
        io, num, result,
        string::String,
        vec::Vec,
    },
    serde_json, webpki,
};
use frame_types::UntrustedStatus;

pub type Result<T> = result::Result<T, FrameRAError>;

#[derive(Debug)]
pub enum FrameRAError {
    ParseIntError(num::ParseIntError),
    IoError(io::Error),
    AnyhowError(anyhow::Error),
    Base64Error(base64::DecodeError),
    SerdeJsonError(serde_json::Error),
    WebpkiJsonError(webpki::Error),
    HttpReqError(http_req::error::Error),
    OcallError {
        status: sgx_types::sgx_status_t,
        function: &'static str,
    },
    UntrustedError {
        status: UntrustedStatus,
        function: &'static str,
    },
    StatusCodeError(http_req::response::Response),
    ApiVersionError(u64),
    QuoteStatusError(String),
    NotFoundisvEnclaveQuoteStatusError,
    BlankCertError,
    VerifyReportError(sgx_types::sgx_status_t),
    VerifyQuoteError {
        rhs: Vec<u8>,
        lhs: Vec<u8>,
    },
    Others(sgx_types::sgx_status_t),
}

impl Error for FrameRAError {}

impl Display for FrameRAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameRAError::ParseIntError(err) => write!(f, "Parse int error: {}", err),
            FrameRAError::IoError(err) => write!(f, "I/O error: {}", err),
            FrameRAError::AnyhowError(err) => write!(f, "Anyhow error: {}", err),
            FrameRAError::Base64Error(err) => write!(f, "base64 error: {}", err),
            FrameRAError::SerdeJsonError(err) => write!(f, "serde json error: {}", err),
            FrameRAError::WebpkiJsonError(err) => write!(f, "web pki error: {}", err),
            FrameRAError::HttpReqError(err) => write!(f, "http req error: {}", err),
            FrameRAError::OcallError{status, function} => write!(f, "Ocall Error: function: {:?}, status: {:?}", function, status),
            FrameRAError::UntrustedError{status, function} => write!(f, "Error caused in untrusted part: function: {:?}, status: {:?}", function, status),
            FrameRAError::StatusCodeError(resp) => write!(f, "The status code indicates that it's not Successful, response: {:?}", resp),
            FrameRAError::ApiVersionError(ver) => write!(f, "The Remote Attestation API version ({}) is not supported", ver),
            FrameRAError::QuoteStatusError(status) => write!(f, "Invalid Enclave Quote Status: {}", status),
            FrameRAError::NotFoundisvEnclaveQuoteStatusError => write!(f, "Failed to fetch isvEnclaveQuoteStatus from attestation report"),
            FrameRAError::BlankCertError => write!(f, "Certificate is blank"),
            FrameRAError::VerifyReportError(status) => write!(f, "qe_report is not valid: {}", status),
            FrameRAError::VerifyQuoteError{rhs, lhs} => write!(f, "received quote is modified or replayed: report.data[..32]: {:?}, SHA256(p_nonce||p_quote): {:?}", rhs, lhs),
            FrameRAError::Others(status) => write!(f, "{}", status),
        }
    }
}

impl From<anyhow::Error> for FrameRAError {
    fn from(err: anyhow::Error) -> Self {
        FrameRAError::AnyhowError(err)
    }
}

impl From<num::ParseIntError> for FrameRAError {
    fn from(err: num::ParseIntError) -> Self {
        FrameRAError::ParseIntError(err)
    }
}

impl From<io::Error> for FrameRAError {
    fn from(err: io::Error) -> Self {
        FrameRAError::IoError(err)
    }
}
impl From<base64::DecodeError> for FrameRAError {
    fn from(err: base64::DecodeError) -> Self {
        FrameRAError::Base64Error(err)
    }
}
impl From<serde_json::Error> for FrameRAError {
    fn from(err: serde_json::Error) -> Self {
        FrameRAError::SerdeJsonError(err)
    }
}
impl From<webpki::Error> for FrameRAError {
    fn from(err: webpki::Error) -> Self {
        FrameRAError::WebpkiJsonError(err)
    }
}
impl From<http_req::error::Error> for FrameRAError {
    fn from(err: http_req::error::Error) -> Self {
        FrameRAError::HttpReqError(err)
    }
}
