#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(all(feature = "sgx", not(feature = "std")))]
#[macro_use]
extern crate sgx_tstd;

#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub(crate) mod stdlib {
    pub(crate) use anyhow_std as anyhow;
    pub(crate) use base64_std as base64;
    pub(crate) use http_req_std as http_req;
    pub(crate) use rustls_std as rustls;
    pub(crate) use serde_json_std as serde_json;
    pub(crate) use serde_std as serde;
    pub(crate) use std as localstd;
    pub(crate) use webpki_std as webpki;
}
#[cfg(all(feature = "sgx", not(feature = "std")))]
pub(crate) mod sgxlib {
    pub(crate) use anyhow_sgx as anyhow;
    pub(crate) use base64_sgx as base64;
    pub(crate) use http_req_sgx as http_req;
    pub(crate) use rustls_sgx as rustls;
    pub(crate) use serde_json_sgx as serde_json;
    pub(crate) use serde_sgx as serde;
    pub(crate) use sgx_tstd as localstd;
    pub(crate) use webpki_sgx as webpki;
}

#[cfg(all(feature = "sgx", not(feature = "std")))]
pub(crate) use crate::sgxlib::*;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub(crate) use crate::stdlib::*;

mod client;
mod error;
mod quote;

pub use crate::client::AttestedReport;
pub use crate::error::FrameRAError as Error;
pub use crate::quote::{EncodedQuote, QuoteTarget};
