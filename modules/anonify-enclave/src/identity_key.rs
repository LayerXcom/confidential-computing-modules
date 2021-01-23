//! This module contains enclave specific cryptographic logics.

use crate::error::Result;
use anonify_ecall_types::*;
use codec::Encode;
use frame_common::{crypto::rand_assign, state_types::StateType, traits::Keccak256};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_treekem::{DhPrivateKey, DhPubKey, EciesCiphertext};
use secp256k1::{
    self, util::SECRET_KEY_SIZE, Message, PublicKey, RecoveryId, SecretKey, Signature,
};
use sgx_types::sgx_report_data_t;
use std::prelude::v1::Vec;

const HASHED_PUBKEY_SIZE: usize = 20;
const ENCRYPTING_KEY_SIZE: usize = 33;
const FILLED_REPORT_DATA_SIZE: usize = HASHED_PUBKEY_SIZE + ENCRYPTING_KEY_SIZE;
const REPORT_DATA_SIZE: usize = 64;

#[derive(Debug, Clone, Default)]
pub struct EncryptingKeyGetter;

impl EnclaveEngine for EncryptingKeyGetter {
    type EI = input::GetEncryptingKey;
    type EO = output::ReturnEncryptingKey;

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let encrypting_key = enclave_context.encrypting_key();

        Ok(output::ReturnEncryptingKey::new(encrypting_key))
    }
}

/// Enclave Identity Key
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnclaveIdentityKey {
    signing_privkey: SecretKey,
    decrypting_privkey: DhPrivateKey,
}

impl EnclaveIdentityKey {
    pub fn new() -> Result<Self> {
        let signing_privkey = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            rand_assign(&mut ret)?;

            if let Ok(key) = SecretKey::parse(&ret) {
                break key;
            }
        };

        let decrypting_privkey = DhPrivateKey::from_random()?;

        Ok(EnclaveIdentityKey {
            signing_privkey,
            decrypting_privkey,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<(Signature, RecoveryId)> {
        let msg = Message::parse_slice(msg)?;
        let sig = secp256k1::sign(&msg, &self.signing_privkey)?;
        Ok(sig)
    }

    pub fn decrypt(&self, ciphertext: EciesCiphertext) -> Result<Vec<u8>> {
        ciphertext
            .decrypt(&self.decrypting_privkey)
            .map_err(Into::into)
    }

    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.signing_privkey)
    }

    pub fn encrypting_key(&self) -> DhPubKey {
        DhPubKey::from_private_key(&self.decrypting_privkey)
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
        report_data[..HASHED_PUBKEY_SIZE].copy_from_slice(&self.verifying_key_into_array()[..]);
        report_data[HASHED_PUBKEY_SIZE..FILLED_REPORT_DATA_SIZE]
            .copy_from_slice(&&self.encrypting_key_into_vec()[..]);

        Ok(sgx_report_data_t { d: report_data })
    }

    fn verifying_key_into_array(&self) -> [u8; HASHED_PUBKEY_SIZE] {
        let pubkey = &self.verifying_key().serialize()[1..];
        let account_id = &pubkey.keccak256()[12..];
        assert_eq!(account_id.len(), HASHED_PUBKEY_SIZE);
        let mut res = [0u8; HASHED_PUBKEY_SIZE];
        res.copy_from_slice(account_id);
        res
    }

    fn encrypting_key_into_vec(&self) -> Vec<u8> {
        let res = self.encrypting_key().encode();
        assert_eq!(res.len(), ENCRYPTING_KEY_SIZE);
        res
    }
}
