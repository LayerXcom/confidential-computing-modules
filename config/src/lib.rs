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
use crate::localstd::{env, string::String, vec::Vec};

#[cfg(feature = "sgx")]
lazy_static! {
    pub static ref IAS_ROOT_CERT: Vec<u8> = {
        let ias_root_cert = include_bytes!("../ias_root_cert.pem");
        let pem = pem::parse(ias_root_cert).expect("Cannot parse PEM File");
        pem.contents
    };
    pub static ref ENCLAVE_MEASUREMENT: EnclaveMeasurement = {
        let pkg_name = env::var("ENCLAVE_PKG_NAME").unwrap_or_default();
        let measurement_file_path = format!("../../.anonify/{}.txt", pkg_name);
        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
}

#[cfg(feature = "sgx")]
#[derive(Debug, Clone, Copy)]
pub struct EnclaveMeasurement {
    mr_signer: [u8; 32],
    mr_enclave: [u8; 32],
}

#[cfg(feature = "sgx")]
impl EnclaveMeasurement {
    pub fn new_from_dumpfile(content: String) -> Self {
        let lines: Vec<&str> = content.split("\n").collect();
        let mr_signer_index = lines
            .iter()
            .position(|&line| line == "mrsigner->value:")
            .expect("mrsigner must be included");
        let mr_enclave_index = lines
            .iter()
            .position(|&line| line == "metadata->enclave_css.body.enclave_hash.m:")
            .expect("mrenclave must be included");

        let mr_signer = Self::parse_measurement(&lines[..], mr_signer_index);
        let mr_enclave = Self::parse_measurement(&lines[..], mr_enclave_index);

        Self {
            mr_signer,
            mr_enclave,
        }
    }

    fn parse_measurement(lines: &[&str], index: usize) -> [u8; 32] {
        let v: Vec<u8> = [lines[index + 1], lines[index + 2]]
            .concat()
            .split_whitespace()
            .map(|e| hex::decode(&e[2..]).unwrap()[0])
            .collect();

        let mut res = [0u8; 32];
        res.copy_from_slice(&v);
        res
    }

    pub fn mr_signer(&self) -> [u8; 32] {
        self.mr_signer
    }

    pub fn mr_enclave(&self) -> [u8; 32] {
        self.mr_enclave
    }
}
