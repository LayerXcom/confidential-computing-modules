//! This module contains enclave specific cryptographic logics.

use sgx_types::sgx_report_data_t;
use std::prelude::v1::Vec;
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM};
use secp256k1::{
    self, Message, Signature, SecretKey, PublicKey,
    util::SECRET_KEY_SIZE,
};
use anonify_common::{Keccak256, IV_SIZE, sgx_rand_assign};
use anonify_app_preluder::{CIPHERTEXT_SIZE, Ciphertext};
use crate::error::Result;

const NONCE_SIZE: usize = 32;
const ADDRESS_SIZE: usize = 20;
const FILLED_REPORT_DATA_SIZE: usize = ADDRESS_SIZE + NONCE_SIZE;
const REPORT_DATA_SIZE: usize = 64;

/// Enclave Identity Key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnclaveIdentityKey {
    secret: SecretKey,
    nonce: [u8; NONCE_SIZE],
}

impl EnclaveIdentityKey {
    pub fn new() -> Result<Self> {
        let secret = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            sgx_rand_assign(&mut ret)?;

            match SecretKey::parse(&ret) {
                Ok(key) => break key,
                Err(_) => (),
            }
        };

        let mut nonce = [0u8; NONCE_SIZE];
        sgx_rand_assign(&mut nonce)?;

        Ok(EnclaveIdentityKey {
            secret,
            nonce,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let msg = Message::parse_slice(msg)?;
        let sig = secp256k1::sign(&msg, &self.secret)?;
        Ok(sig.0)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secret)
    }

    /// Generate a value of REPORTDATA field in REPORT struct.
    /// REPORTDATA consists of a compressed secp256k1 public key and nonce.
    /// The public key is used for verifying signature on-chain to attest enclave's execution w/o a whole REPORT data,
    /// because this enclave identity key is binding to enclave's code.
    /// The nonce is used for preventing from replay attacks.
    /// 20bytes: Address
    /// 32bytes: nonce
    /// 12bytes: zero padding
    pub fn report_data(&self) -> Result<sgx_report_data_t> {
        let mut report_data = [0u8; REPORT_DATA_SIZE];
        report_data[..ADDRESS_SIZE].copy_from_slice(&self.address()[..]);
        report_data[ADDRESS_SIZE..FILLED_REPORT_DATA_SIZE].copy_from_slice(&&self.nonce[..]);

        Ok(sgx_report_data_t {
            d: report_data
        })
    }

    fn address(&self) -> [u8; ADDRESS_SIZE] {
        let pubkey = &self.public_key().serialize();
        let address = &pubkey.keccak256()[12..];
        assert_eq!(address.len(), ADDRESS_SIZE);
        let mut res = [0u8; ADDRESS_SIZE];
        res.copy_from_slice(address);
        res
    }
}
