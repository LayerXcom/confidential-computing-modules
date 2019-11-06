use sgx_types::sgx_status_t;
use failure::{Backtrace, Context, Fail};
use std::io;
use std::fmt;
use std::fmt::Display;

#[derive(Debug)]
pub struct HostError {
    inner: Context<HostErrorKind>,
}

#[derive(Copy, Clone, Debug, Fail)]
pub enum HostErrorKind {
    #[fail(display = "SGX Ecall Failed function: {}, status: {}", function, status)]
    Sgx {
        status: sgx_status_t,
        function: &'static str,
    },
    #[fail(display = "IO error")]
    Io,
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
    pub fn kind(&self) -> HostErrorKind {
        *self.inner.get_context()
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
