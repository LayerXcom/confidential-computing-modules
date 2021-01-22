//! Keyfile operations such as signing.
use crate::{
    error::{Result, WalletError},
    SerdeBytes,
};
use anyhow::anyhow;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, SECRET_KEY_LENGTH};
use parity_crypto as crypto;
use parity_crypto::Keccak256;
use rand::Rng;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyFile {
    /// Unique Keyfile name which is used for filename.
    /// If this keyfile is not stored yet, no name exits.
    pub file_name: Option<String>,
    /// User defined account name
    pub account_name: String,
    /// base64-encoded address
    pub base64_address: String,
    /// Keyfile version
    pub version: u32,
    /// Encrypted private key
    pub encrypted_key: KeyCiphertext,
}

impl KeyFile {
    pub fn new<R: Rng>(
        account_name: &str,
        version: u32,
        password: &[u8],
        iters: u32,
        key_pair: &Keypair,
        rng: &mut R,
    ) -> Result<Self> {
        let encrypted_key = KeyCiphertext::encrypt(&key_pair, password, iters, rng)?;
        let base64_address = Self::keypair_to_encoded_addr(&key_pair);

        Ok(KeyFile {
            file_name: None,
            account_name: account_name.to_string(),
            base64_address,
            version,
            encrypted_key,
        })
    }

    pub fn new_from_seed<R: Rng>(
        account_name: &str,
        version: u32,
        password: &[u8],
        iters: u32,
        seed: &[u8],
        rng: &mut R,
    ) -> Result<Self> {
        assert!(seed.len() > SECRET_KEY_LENGTH);
        let secret =
            SecretKey::from_bytes(&seed[..SECRET_KEY_LENGTH]).map_err(|e| anyhow!("{:?}", e))?;
        let public = PublicKey::from(&secret);
        let key_pair = Keypair { secret, public };

        Self::new(account_name, version, password, iters, &key_pair, rng)
    }

    pub fn get_key_pair(&self, password: &[u8]) -> Result<Keypair> {
        let key_pair = self.encrypted_key.decrypt(password)?;
        Ok(key_pair)
    }

    fn keypair_to_encoded_addr(key_pair: &Keypair) -> String {
        use frame_common::crypto::AccountId;

        let user_address = AccountId::from_pubkey(&key_pair.public);
        user_address.base64_encode()
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct KeyCiphertext {
    pub ciphertext: SerdeBytes,
    pub mac: SerdeBytes,
    pub salt: SerdeBytes,
    pub iv: SerdeBytes,
    pub iters: u32,
}

impl KeyCiphertext {
    /// Encrypt plain bytes data
    /// Currently using `parity-crypto`.
    pub fn encrypt<R: Rng>(
        key_pair: &Keypair,
        password: &[u8],
        iters: u32,
        rng: &mut R,
    ) -> Result<Self> {
        assert!(iters != 0);
        let salt: [u8; 32] = rng.gen();
        let iv: [u8; 16] = rng.gen();

        let (derived_left, derived_right) = crypto::derive_key_iterations(password, &salt, iters);
        let key_pair_bytes = key_pair.to_bytes();
        let mut ciphertext: SmallVec<[u8; 32]> = SmallVec::from_vec(vec![0; key_pair_bytes.len()]);

        crypto::aes::encrypt_128_ctr(&derived_left, &iv, &key_pair_bytes[..], &mut *ciphertext)
            .map_err(crypto::Error::from)?;
        let mac = crypto::derive_mac(&derived_right, &*ciphertext).keccak256();

        Ok(KeyCiphertext {
            ciphertext: ciphertext.into(),
            mac: mac.into(),
            salt: salt.into(),
            iv: iv.into(),
            iters,
        })
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Keypair> {
        let (derived_left, derived_right) =
            crypto::derive_key_iterations(password, &self.salt.0[..], self.iters);
        let mac = crypto::derive_mac(&derived_right, &self.ciphertext.0).keccak256();

        if !crypto::is_equal(&mac, &self.mac.0) {
            return Err(WalletError::InvalidPassword);
        }

        let mut plain: SmallVec<[u8; 32]> = SmallVec::from_vec(vec![0; self.ciphertext.0.len()]);
        crypto::aes::decrypt_128_ctr(&derived_left, &self.iv.0, &self.ciphertext.0, &mut plain)
            .map_err(crypto::Error::from)?;

        let key_pair = Keypair::from_bytes(&plain.to_vec()[..]).map_err(|e| anyhow!("{:?}", e))?;

        Ok(key_pair)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Default, Clone)]
pub struct IndexFile {
    /// Default account index
    pub default_index: u32,

    /// Maximum account index
    pub max_index: u32,

    /// Default keyfile name
    pub default_keyfile_name: String,

    /// Mapping account_name to keyfile_name
    pub map_account_keyfile: HashMap<String, (String, u32)>,
}

impl IndexFile {
    pub fn set_default_index(
        mut self,
        new_index: u32,
        new_keyfile_name: &str,
        new_account_name: &str,
    ) -> Self {
        self.map_account_keyfile.extend(Some((
            new_account_name.to_string(),
            (new_keyfile_name.to_string(), new_index),
        )));

        IndexFile {
            default_index: new_index,
            max_index: self.max_index,
            default_keyfile_name: new_keyfile_name.to_string(),
            map_account_keyfile: self.map_account_keyfile,
        }
    }

    pub fn next_index(mut self, keyfile_name: &str, account_name: &str) -> Self {
        let next_index = self.max_index + 1;
        self.map_account_keyfile.extend(Some((
            account_name.to_string(),
            (keyfile_name.to_string(), next_index),
        )));

        IndexFile {
            default_index: next_index,
            max_index: next_index,
            default_keyfile_name: keyfile_name.to_string(),
            map_account_keyfile: self.map_account_keyfile,
        }
    }
}
