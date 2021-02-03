//! This module contains enclave specific cryptographic logics.

use crate::error::Result;
use anonify_ecall_types::*;
use frame_common::{crypto::rand_assign, state_types::StateType, traits::Keccak256};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_sodium::{SodiumCiphertext, SodiumPrivateKey, SodiumPubKey, SODIUM_PUBLIC_KEY_SIZE};
use rand_core::{CryptoRng, RngCore};
use secp256k1::{
    self, util::SECRET_KEY_SIZE, Message, PublicKey, RecoveryId, SecretKey, Signature,
};
use sgx_types::sgx_report_data_t;
use std::prelude::v1::Vec;

const HASHED_PUBKEY_SIZE: usize = 20;
const ENCLAVE_ENCRYPTION_KEY_SIZE: usize = SODIUM_PUBLIC_KEY_SIZE;
const FILLED_REPORT_DATA_SIZE: usize = HASHED_PUBKEY_SIZE + ENCLAVE_ENCRYPTION_KEY_SIZE;
const REPORT_DATA_SIZE: usize = 64;

#[derive(Debug, Clone, Default)]
pub struct EncryptionKeyGetter;

impl EnclaveEngine for EncryptionKeyGetter {
    type EI = input::Empty;
    type EO = output::ReturnEncryptionKey;

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let enclave_encryption_key = enclave_context.enclave_encryption_key();

        Ok(output::ReturnEncryptionKey::new(enclave_encryption_key))
    }
}

/// Enclave Key
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnclaveKey {
    signing_privkey: SecretKey,
    decryption_privkey: SodiumPrivateKey,
}

impl EnclaveKey {
    pub fn new<CR>(csprng: &mut CR) -> Result<Self>
    where
        CR: RngCore + CryptoRng,
    {
        let signing_privkey = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            rand_assign(&mut ret)?;

            if let Ok(key) = SecretKey::parse(&ret) {
                break key;
            }
        };

        let decryption_privkey = SodiumPrivateKey::from_random(csprng)?;

        Ok(EnclaveKey {
            signing_privkey,
            decryption_privkey,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<(Signature, RecoveryId)> {
        let msg = Message::parse_slice(msg)?;
        let sig = secp256k1::sign(&msg, &self.signing_privkey)?;
        Ok(sig)
    }

    pub fn decrypt(&self, ciphertext: SodiumCiphertext) -> Result<Vec<u8>> {
        ciphertext
            .decrypt(&self.decryption_privkey)
            .map_err(Into::into)
    }

    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.signing_privkey)
    }

    pub fn enclave_encryption_key(&self) -> SodiumPubKey {
        self.decryption_privkey.public_key()
    }

    /// Generate a value of REPORTDATA field in REPORT struct.
    /// REPORTDATA consists of a hashed signing public key and a encryption public key.
    /// The hashed signing public key is used for verifying signature on-chain to attest enclave's execution w/o a whole REPORT data,
    /// because this enclave key is binding to enclave's code.
    /// The encryption public key is used for secure communication between clients and TEE.
    /// 20 bytes: hashed signing public key
    /// 32 bytes: encryption public key
    /// 11 bytes: zero padding
    pub fn report_data(&self) -> Result<sgx_report_data_t> {
        let mut report_data = [0u8; REPORT_DATA_SIZE];
        report_data[..HASHED_PUBKEY_SIZE].copy_from_slice(&self.verifying_key_into_array()[..]);
        report_data[HASHED_PUBKEY_SIZE..FILLED_REPORT_DATA_SIZE]
            .copy_from_slice(&self.encode_enclave_encryption_key()[..]);

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

    fn encode_enclave_encryption_key(&self) -> [u8; ENCLAVE_ENCRYPTION_KEY_SIZE] {
        self.enclave_encryption_key().to_bytes()
    }
}
