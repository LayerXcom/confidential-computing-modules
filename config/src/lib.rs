#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![allow(unused_imports)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;
#[cfg(feature = "sgx")]
use anyhow_sgx as local_anyhow;
#[cfg(feature = "std")]
use anyhow_std as local_anyhow;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as local_serde;
#[cfg(feature = "std")]
use serde_std as local_serde;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use toml_sgx as local_toml;
#[cfg(feature = "std")]
use toml_std as local_toml;
#[macro_use]
extern crate lazy_static;

pub mod constants;

pub use crate::constants::*;
use crate::local_anyhow::Result;
use crate::localstd::{env, string::String, untrusted::fs, vec::Vec};

#[cfg(feature = "sgx")]
lazy_static! {
    pub static ref IAS_ROOT_CERT: Vec<u8> = {
        let ias_root_cert = include_bytes!("../ias_root_cert.pem");
        let pem = pem::parse(ias_root_cert).expect("Cannot parse PEM File");
        pem.contents
    };
    pub static ref ENCLAVE_MEASUREMENT: EnclaveMeasurement = {
        let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("ENCLAVE_PKG_NAME is not set");
        let measurement_file_path = format!("../../.anonify/{}_measurement.txt", pkg_name);
        let content =
            fs::read_to_string(&measurement_file_path).expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content).unwrap()
    };
}

#[cfg(feature = "sgx")]
pub struct EnclaveMeasurement {
    mr_signer: [u8; sgx_types::SGX_HASH_SIZE],
    mr_enclave: [u8; sgx_types::SGX_HASH_SIZE],
}

impl EnclaveMeasurement {
    pub fn new_from_dumpfile(content: String) -> Result<Self> {
        let lines: Vec<&str> = content.split("\n").collect();
        unimplemented!();
    }
}
