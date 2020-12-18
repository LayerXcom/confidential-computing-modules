use frame_types::UntrustedStatus;
use std::io;
use std::vec::Vec;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, FrameRAError>;

#[derive(Error, Debug)]
pub enum FrameRAError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),

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

    #[error("qe_report is not valid: {0}")]
    VerifyReportError(sgx_types::sgx_status_t),
    #[error("received quote is modified or replayed: report.data[..32]: {rhs:?}, SHA256(p_nonce||p_quote): {lhs:?}")]
    VerifyQuoteError { rhs: Vec<u8>, lhs: Vec<u8> },
    #[error("{0}")]
    Others(sgx_types::sgx_status_t),
}
