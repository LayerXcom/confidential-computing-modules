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
#[macro_use]
extern crate lazy_static;

use crate::local_anyhow::Result;
use crate::localstd::{env, ffi::OsStr, path::PathBuf, string::String, vec::Vec};

#[cfg(feature = "sgx")]
lazy_static! {
    pub static ref IAS_ROOT_CERT: Vec<u8> = {
        let ias_root_cert = include_bytes!("../ias_root_cert.pem");
        let pem = pem::parse(ias_root_cert).expect("Cannot parse PEM File");
        pem.contents
    };
    pub static ref ENCLAVE_SIGNED_SO: PathBuf = {
        let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("ENCLAVE_PKG_NAME is not set");
        let mut measurement_file_path = PJ_ROOT_DIR.clone();

        let measurement_file = match env::var("BACKUP") {
            Ok(backup) if backup == "disable" => {
                format!(".anonify/{}.backup_disabled.signed.so", pkg_name)
            }
            _ => format!(".anonify/{}.signed.so", pkg_name),
        };

        measurement_file_path.push(measurement_file);
        measurement_file_path
    };
    pub static ref ENCLAVE_MEASUREMENT: EnclaveMeasurement = {
        let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("ENCLAVE_PKG_NAME is not set");
        let mut measurement_file_path = PJ_ROOT_DIR.clone();

        let measurement_file = match env::var("BACKUP") {
            Ok(backup) if backup == "disable" => {
                format!(".anonify/{}_backup_disabled_measurement.txt", pkg_name)
            }
            _ => format!(".anonify/{}_measurement.txt", pkg_name),
        };

        measurement_file_path.push(measurement_file);
        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
    pub static ref ENCLAVE_MEASUREMENT_KEY_VAULT: EnclaveMeasurement = {
        let pkg_name = "secret_backup";
        let mut measurement_file_path = PJ_ROOT_DIR.clone();
        let measurement_file = format!(".anonify/{}_measurement.txt", pkg_name);
        measurement_file_path.push(measurement_file);
        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
    pub static ref ENCLAVE_MEASUREMENT_ERC20: EnclaveMeasurement = {
        let pkg_name = "erc20";
        let mut measurement_file_path = PJ_ROOT_DIR.clone();

        let measurement_file = match env::var("BACKUP") {
            Ok(backup) if backup == "disable" => {
                format!(".anonify/{}_backup_disabled_measurement.txt", pkg_name)
            }
            _ => format!(".anonify/{}_measurement.txt", pkg_name),
        };

        measurement_file_path.push(measurement_file);
        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
    pub static ref SPID: String = env::var("SPID").expect("SPID is not set");
    pub static ref SUB_KEY: String = env::var("SUB_KEY").expect("SUB_KEY is not set");
}

lazy_static! {
    pub static ref PJ_ROOT_DIR: PathBuf = {
        let mut current_dir = env::current_dir().unwrap();
        loop {
            if current_dir.file_name() == Some(OsStr::new("anonify")) {
                break;
            }
            if !current_dir.pop() {
                break;
            }
        }

        current_dir
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
