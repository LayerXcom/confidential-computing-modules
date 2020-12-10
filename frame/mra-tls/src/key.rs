use anyhow::Result;
use sgx_tcrypto::SgxEccHandle;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
use std::vec::Vec;
use yasna::models::ObjectIdentifier;

pub struct NistP256KeyPair {
    priv_key: sgx_ec256_private_t,
    pub_key: sgx_ec256_public_t,
}

impl NistP256KeyPair {
    pub fn new() -> Result<Self> {
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open()?;
        let (priv_key, pub_key) = ecc_handle.create_key_pair()?;
        ecc_handle.close()?;
        Ok(Self { priv_key, pub_key })
    }

    pub fn private_key_into_der(&self) -> Vec<u8> {
        // http://oid-info.com/get/1.2.840.10045.2.1
        let ec_public_key_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]);
        // http://oid-info.com/get/1.2.840.10045.3.1.7
        let prime256v1_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);

        unimplemented!();
    }
}
