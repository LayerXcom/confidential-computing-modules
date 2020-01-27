//! This module containes enclave specific cryptographic logics.

use std::{
    prelude::v1::Vec,
    io::Read,
};
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM};
use crate::error::Result;

lazy_static! {
    pub static ref SYMMETRIC_KEY: SymmetricKey = Default::default();
}

/// The size of the symmetric 256 bit key we use for encryption in bytes.
pub const SYMMETRIC_KEY_SIZE: usize = 32;

/// symmetric key we use for encryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_SIZE]);

impl SymmetricKey {
    pub fn new_rand() -> Result<Self> {
        let mut buf = [0u8; SYMMETRIC_KEY_SIZE];
        rng_gen(&mut buf[..])?;

        Ok(SymmetricKey(buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// The size of initialization vector for AES-256-GCM.
pub const IV_SIZE: usize = 12;

/// Generating a random number inside the enclave.
pub fn rng_gen(rand: &mut [u8]) -> Result<()> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)?;
    Ok(())
}

/// Encryption with AES-256-GCM.
pub fn encrypt_aes_256_gcm(msg: Vec<u8>, key: &SymmetricKey) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_SIZE];
    rng_gen(&mut iv)?;

    let ub_key = UnboundKey::new(&AES_256_GCM, key.as_bytes())?;
    let nonce = Nonce::assume_unique_for_key(iv);
    let nonce_seq = OneNonceSequence::new(nonce);

    let mut s_key = aead::SealingKey::new(ub_key, nonce_seq);
    let mut data = msg;
    s_key.seal_in_place_append_tag(Aad::empty(), &mut data)?;
    data.extend_from_slice(&iv);

    Ok(data)
}

/// Decryption with AES-256-GCM.
pub fn decrypt_aes_256_gcm(cipheriv: Vec<u8>, key: &SymmetricKey) -> Result<Vec<u8>> {
    let ub_key = UnboundKey::new(&AES_256_GCM, key.as_bytes())?;
    let (ciphertext, iv) = cipheriv.split_at(cipheriv.len() - IV_SIZE);

    let nonce = Nonce::try_assume_unique_for_key(iv)?;
    let nonce_seq = OneNonceSequence::new(nonce);
    let mut o_key = aead::OpeningKey::new(ub_key, nonce_seq);

    let mut ciphertext = ciphertext.to_vec();
    o_key.open_in_place(Aad::empty(), &mut ciphertext)?;

    Ok(ciphertext)
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


