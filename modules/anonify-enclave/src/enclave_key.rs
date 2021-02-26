//! This module contains enclave specific cryptographic logics.

use crate::error::{EnclaveError, Result};
use anonify_ecall_types::*;
use frame_common::{crypto::rand_assign, state_types::StateType, traits::Keccak256};
use frame_enclave::EnclaveEngine;
use frame_mra_tls::{
    key_vault::request::{
        KeyVaultCmd, KeyVaultRequest, RecoverEnclaveDecryptionKeyRequestBody,
        StoreEnclaveDecryptionKeyRequestBody,
    },
    Client, ClientConfig,
};
use frame_runtime::traits::*;
use frame_sodium::{
    rng::SgxRng, SodiumCiphertext, SodiumPrivateKey, SodiumPubKey, SODIUM_PUBLIC_KEY_SIZE,
};
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
        let enclave_encryption_key = enclave_context.enclave_encryption_key()?;

        Ok(output::ReturnEncryptionKey::new(enclave_encryption_key))
    }
}

/// Enclave Key
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnclaveKey {
    signing_privkey: SecretKey,
    decryption_privkey: Option<SodiumPrivateKey>,
}

impl EnclaveKey {
    pub fn new() -> Result<Self> {
        let signing_privkey = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            rand_assign(&mut ret)?;

            if let Ok(key) = SecretKey::parse(&ret) {
                break key;
            }
        };

        Ok(EnclaveKey {
            signing_privkey,
            decryption_privkey: None,
        })
    }

    /// If you can get the dec_key, it is the initialization at the time of recovery,
    /// otherwise, a new dec_key is generated.
    pub fn set_dec_key_by_owner(
        mut self,
        client_config: &ClientConfig,
        key_vault_endpoint: &str,
    ) -> Result<Self> {
        let decryption_privkey = match Self::get_dec_key(&client_config, &key_vault_endpoint) {
            Ok(dec_key) => dec_key,
            Err(_e) => {
                let mut rng = SgxRng::new()?;
                SodiumPrivateKey::from_random(&mut rng)?
            }
        };

        self.decryption_privkey = Some(decryption_privkey);
        Ok(self)
    }

    /// Get dec_key from key-vault node in initialization when joining newly.
    pub fn set_dec_key_by_member(
        mut self,
        client_config: &ClientConfig,
        key_vault_endpoint: &str,
    ) -> Result<Self> {
        let decryption_privkey = Self::get_dec_key(&client_config, &key_vault_endpoint)?;

        self.decryption_privkey = Some(decryption_privkey);
        Ok(self)
    }

    /// Sealing locally, make it persistent, and save it in the key-vault node as well
    pub fn store_dec_key(
        &self,
        client_config: &ClientConfig,
        key_vault_endpoint: &str,
    ) -> Result<()> {
        let mut mra_tls_client = Client::new(key_vault_endpoint, &client_config)?;
        let dec_key = self
            .decryption_privkey
            .as_ref()
            .ok_or_else(|| EnclaveError::NotSetEnclaveDecKeyError)?;
        let key_vault_request = KeyVaultRequest::new(
            KeyVaultCmd::StoreEnclaveDecryptionKey,
            StoreEnclaveDecryptionKeyRequestBody::new(dec_key.clone()),
        );
        let _resp: serde_json::Value = mra_tls_client.send_json(key_vault_request)?;

        Ok(())
    }

    /// After trying to get the local sealed dec_key, get it to key-vault node
    fn get_dec_key(
        client_config: &ClientConfig,
        key_vault_endpoint: &str,
    ) -> Result<SodiumPrivateKey> {
        let mut mra_tls_client = Client::new(key_vault_endpoint, &client_config)?;
        let get_dec_key_request = KeyVaultRequest::new(
            KeyVaultCmd::RecoverEnclaveDecrptionKey,
            RecoverEnclaveDecryptionKeyRequestBody::default(),
        );
        let dec_key: SodiumPrivateKey = mra_tls_client.send_json(get_dec_key_request)?;

        Ok(dec_key)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<(Signature, RecoveryId)> {
        let msg = Message::parse_slice(msg)?;
        let sig = secp256k1::sign(&msg, &self.signing_privkey)?;
        Ok(sig)
    }

    pub fn decrypt(&self, ciphertext: SodiumCiphertext) -> Result<Vec<u8>> {
        let dec_key = self
            .decryption_privkey
            .as_ref()
            .ok_or_else(|| EnclaveError::NotSetEnclaveDecKeyError)?;
        ciphertext.decrypt(&dec_key).map_err(Into::into)
    }

    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.signing_privkey)
    }

    pub fn enclave_encryption_key(&self) -> Result<SodiumPubKey> {
        let enclave_dec_key = self
            .decryption_privkey
            .as_ref()
            .ok_or_else(|| EnclaveError::NotSetEnclaveDecKeyError)?;
        Ok(enclave_dec_key.public_key())
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
            .copy_from_slice(&self.encode_enclave_encryption_key()?[..]);

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

    fn encode_enclave_encryption_key(&self) -> Result<[u8; ENCLAVE_ENCRYPTION_KEY_SIZE]> {
        Ok(self.enclave_encryption_key()?.to_bytes())
    }
}
