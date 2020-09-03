//! This module contains enclave specific cryptographic logics.

use sgx_types::sgx_report_data_t;
use std::prelude::v1::Vec;
use secp256k1::{
    self, Message, Signature, SecretKey, PublicKey,
    util::SECRET_KEY_SIZE,
};
use frame_common::{
    crypto::sgx_rand_assign,
    traits::Keccak256,
};
use frame_treekem::{DhPrivateKey, DhPubKey};
use crate::error::Result;

const HASHED_PUBKEY_SIZE: usize = 20;
const ENCRYPTING_KEY_SIZE: usize = 33;
const FILLED_REPORT_DATA_SIZE: usize = HASHED_PUBKEY_SIZE + ENCRYPTING_KEY_SIZE;
const REPORT_DATA_SIZE: usize = 64;

/// Enclave Identity Key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnclaveIdentityKey {
    signing_privkey: SecretKey,
    decrypting_privkey: DhPrivateKey,
}

impl EnclaveIdentityKey {
    pub fn new() -> Result<Self> {
        let sign_privkey = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            sgx_rand_assign(&mut ret)?;

            match SecretKey::parse(&ret) {
                Ok(key) => break key,
                Err(_) => (),
            }
        };

        let decrypting_privkey = DhPrivateKey::from_random()?;

        Ok(EnclaveIdentityKey {
            signing_privkey,
            decrypting_privkey,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let msg = Message::parse_slice(msg)?;
        let sig = secp256k1::sign(&msg, &self.signing_privkey)?;
        Ok(sig.0)
    }

    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.signing_privkey)
    }

    pub fn encrypting_key(&self) -> DhPubKey {
        DhPubkey::from_private_key(&self.decrypting_privkey)
    }

    /// Generate a value of REPORTDATA field in REPORT struct.
    /// REPORTDATA consists of a hashed sining public key and a encrypting public key.
    /// The hashed sining public key is used for verifying signature on-chain to attest enclave's execution w/o a whole REPORT data,
    /// because this enclave identity key is binding to enclave's code.
    /// The encrypting public key is used for secure communication between clients and TEE.
    /// 20 bytes: hashed sining public key
    /// 33 bytes: encrypting public key
    /// 11 bytes: zero padding
    pub fn report_data(&self) -> Result<sgx_report_data_t> {
        let mut report_data = [0u8; REPORT_DATA_SIZE];
        report_data[..HASHED_PUBKEY_SIZE].copy_from_slice(&self.hashed_pverifying_key_to_array()[..]);
        report_data[HASHED_PUBKEY_SIZE..FILLED_REPORT_DATA_SIZE].copy_from_slice(&&self.encrypting_key_to_array()[..]);

        Ok(sgx_report_data_t {
            d: report_data
        })
    }

    fn hashed_pverifying_key_to_array(&self) -> [u8; HASHED_PUBKEY_SIZE] {
        let pubkey = &self.verifying_key().serialize();
        let address = &pubkey.keccak256()[12..];
        assert_eq!(address.len(), HASHED_PUBKEY_SIZE);
        let mut res = [0u8; HASHED_PUBKEY_SIZE];
        res.copy_from_slice(address);
        res
    }

    fn encrypting_key_to_array(&self) -> [u8; ENCRYPTING_KEY_SIZE] {
        unimplemented!();
    }
}
