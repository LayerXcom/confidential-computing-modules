use sgx_types::sgx_status_t;
use failure::{Backtrace, Context, Fail};
use std::io;
use std::fmt;
use std::fmt::Display;

pub type Result<T> = std::result::Result<T, HostError>;

#[derive(Debug)]
pub struct HostError {
    inner: Context<HostErrorKind>,
}

#[derive(Debug, Fail)]
pub enum HostErrorKind {
    #[fail(display = "SGX Ecall Failed function: {}, status: {}", function, status)]
    Sgx {
        status: sgx_status_t,
        function: &'static str,
    },
    #[fail(display = "Error while decoding the quote = ({})", _0)]
    Quote(&'static str),
    #[fail(display = "Error while using the attestation service info = ({})", _0)]
    AS(String),
    #[fail(display = "IO error")]
    Io,
    #[fail(display = "File error = ({})", _0)]
    File(String),
    #[fail(display = "Reqwest error")]
    Reqwest,
    #[fail(display = "Serde Json error")]
    SerdeJson,
    #[fail(display = "OpenSSL error")]
    OpenSSL,
    #[fail(display = "Hex decoding error")]
    Hex,
    #[fail(display = "Web3 error")]
    Web3,
    #[fail(display = "Web3 Contract error = ({})", _0)]
    Web3Contract(String),
    #[fail(display = "Web3's log data error = ({}), Failed index: {}", msg, index)]
    Web3Log {
        msg: &'static str,
        index: usize,
    },
}

impl Fail for HostError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl HostError {
    pub fn kind(&self) -> &HostErrorKind {
        self.inner.get_context()
    }
}

impl From<HostErrorKind> for HostError {
    fn from(kind: HostErrorKind) -> HostError {
        HostError { inner: Context::new(kind) }
    }
}

impl From<Context<HostErrorKind>> for HostError {
    fn from(inner: Context<HostErrorKind>) -> HostError {
        HostError { inner: inner }
    }
}

impl From<io::Error> for HostError {
    fn from(error: io::Error) -> Self {
        HostError {
            inner: error.context(HostErrorKind::Io),
        }
    }
}

impl From<reqwest::Error> for HostError {
    fn from(error: reqwest::Error) -> Self {
        HostError {
            inner: error.context(HostErrorKind::Reqwest),
        }
    }
}

impl From<serde_json::Error> for HostError {
    fn from(error: serde_json::Error) -> Self {
        HostError {
            inner: error.context(HostErrorKind::SerdeJson),
        }
    }
}

impl From<openssl::error::ErrorStack> for HostError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        HostError {
            inner: error.context(HostErrorKind::OpenSSL),
        }
    }
}

impl From<hex::FromHexError> for HostError {
    fn from(error: hex::FromHexError) -> Self {
        HostError {
            inner: error.context(HostErrorKind::OpenSSL),
        }
    }
}

impl From<web3::Error> for HostError {
    fn from(error: web3::Error) -> Self {
        HostError {
            inner: error.context(HostErrorKind::Web3),
        }
    }
}
