use sgx_types::sgx_status_t;
use failure::{Backtrace, Context, Fail};
use std::io;
use std::fmt;
use std::fmt::Display;

pub type Result<T> = std::result::Result<T, RpcError>;

#[derive(Debug)]
pub struct RpcError {
    inner: Context<RpcErrorKind>,
}

#[derive(Debug, Fail)]
pub enum RpcErrorKind {
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
    #[fail(display = "Rustc-Hex decoding error")]
    RustcHex,
    #[fail(display = "Web3 error")]
    Web3,
    #[fail(display = "Web3 Contract error = ({})", _0)]
    Web3Contract(String),
    #[fail(display = "Web3's log data error = ({}), Failed index: {}", msg, index)]
    Web3Log {
        msg: &'static str,
        index: usize,
    },
    #[fail(display = "{}", _0)]
    Msg(&'static str),
}

impl Fail for RpcError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl RpcError {
    pub fn kind(&self) -> &RpcErrorKind {
        self.inner.get_context()
    }
}

impl From<RpcErrorKind> for RpcError {
    fn from(kind: RpcErrorKind) -> RpcError {
        RpcError { inner: Context::new(kind) }
    }
}

impl From<Context<RpcErrorKind>> for RpcError {
    fn from(inner: Context<RpcErrorKind>) -> RpcError {
        RpcError { inner: inner }
    }
}

impl From<io::Error> for RpcError {
    fn from(error: io::Error) -> Self {
        RpcError {
            inner: error.context(RpcErrorKind::Io),
        }
    }
}

impl From<rustc_hex::FromHexError> for RpcError {
    fn from(error: rustc_hex::FromHexError) -> Self {
        RpcError {
            inner: error.context(RpcErrorKind::RustcHex),
        }
    }
}

impl From<web3::Error> for RpcError {
    fn from(error: web3::Error) -> Self {
        RpcError {
            inner: error.context(RpcErrorKind::Web3),
        }
    }
}
