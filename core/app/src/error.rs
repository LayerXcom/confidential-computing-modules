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
    #[fail(display = "Reqwest error")]
    Reqwest,
    #[fail(display = "Serde Json error")]
    SerdeJson,
}

impl Fail for HostError {
    fn cause(&self) -> Option<&Fail> {
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
