//! This module containes enclave specific cryptographic logics.

use std::{
    prelude::v1::Vec,
    io::Read,
};
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM};
use secp256k1::{SecretKey, PublicKey};
use crate::error::Result;

lazy_static! {
    pub static ref SYMMETRIC_KEY: SymmetricKey = SymmetricKey::new_rand().unwrap();
}

/// The size of the symmetric 256 bit key we use for encryption in bytes.
pub const SYMMETRIC_KEY_SIZE: usize = 32;
/// The size of initialization vector for AES-256-GCM.
pub const IV_SIZE: usize = 12;

const SECRET_SIZE: usize = 32;
const NONCE_SIZE: usize = 32;
const REPORT_DATA_SIZE: usize = SECRET_SIZE + NONCE_SIZE;

/// symmetric key we use for encryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_SIZE]);

impl SymmetricKey {
    pub fn new_rand() -> Result<Self> {
        let mut buf = [0u8; SYMMETRIC_KEY_SIZE];
        sgx_rand_assign(&mut buf[..])?;

        Ok(SymmetricKey(buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Encryption with AES-256-GCM.
    pub fn encrypt_aes_256_gcm(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_SIZE];
        sgx_rand_assign(&mut iv)?;

        let ub_key = UnboundKey::new(&AES_256_GCM, &self.as_bytes())?;
        let nonce = Nonce::assume_unique_for_key(iv);
        let nonce_seq = OneNonceSequence::new(nonce);

        let mut s_key = aead::SealingKey::new(ub_key, nonce_seq);
        let mut data = msg;
        s_key.seal_in_place_append_tag(Aad::empty(), &mut data)?;
        data.extend_from_slice(&iv);

        Ok(data)
    }

    /// Decryption with AES-256-GCM.
    pub fn decrypt_aes_256_gcm(&self, cipheriv: Vec<u8>) -> Result<Vec<u8>> {
        let ub_key = UnboundKey::new(&AES_256_GCM, &self.as_bytes())?;
        let (ciphertext, iv) = cipheriv.split_at(cipheriv.len() - IV_SIZE);

        let nonce = Nonce::try_assume_unique_for_key(iv)?;
        let nonce_seq = OneNonceSequence::new(nonce);
        let mut o_key = aead::OpeningKey::new(ub_key, nonce_seq);

        let mut ciphertext = ciphertext.to_vec();
        o_key.open_in_place(Aad::empty(), &mut ciphertext)?;

        Ok(ciphertext)
    }
}

/// A sequences of unique nonces.
/// See: https://briansmith.org/rustdoc/ring/aead/trait.NonceSequence.html
struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: aead::Nonce) -> Self {
        OneNonceSequence(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified).into()
    }
}

/// Generating a random number inside the enclave.
pub fn sgx_rand_assign(rand: &mut [u8]) -> Result<()> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)?;
    Ok(())
}

/// Enclave Identity Key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EIK {
    secret: SecretKey,
    nonce: [u8; NONCE_SIZE],
}

impl EIK {
    pub fn new() -> Self {
        let secret = loop {
            let mut ret = [0u8; SECRET_SIZE];
            sgx_rand_assign(&mut ret);

            match SecretKey::parse(&ret) {
                Ok(key) => break key,
                Err(_) => (),
            }
        };

        let mut nonce = [0u8; NONCE_SIZE];
        sgx_rand_assign(&mut nonce);

        EIK {
            secret,
            nonce,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secret)
    }

    pub fn report_date(&self) -> [u8; REPORT_DATA_SIZE] {
        let mut report_data = [0u8; REPORT_DATA_SIZE];
        report_data[..32].copy_from_slice(&self.secret.serialize()[..]);
        report_data[32..].copy_from_slice(&self.nonce[..]);

        report_data
    }
}
