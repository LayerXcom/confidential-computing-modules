use anonify_types::{Plaintext, Ciphertext};
use crate::error::Result;
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey};
use std::prelude::v1::Vec;

/// The size of the symmetric 256 bit key we use for encryption (in bytes).
pub const SYMMETRIC_KEY_SIZE: usize = 256 / 8;
/// symmetric key we use for encryption.
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

// Symmetric encryption scheme for state.
pub trait AES256GCM {
    fn encrypt(&self, key: &SymmetricKey) -> Ciphertext;

    fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self;
}

pub fn rng_gen(rand: &mut [u8]) -> Result<()> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)?;
    Ok(())
}


pub fn encrypt_256_gcm(mut msg: Vec<u8>, key: &SymmetricKey) -> Result<Vec<u8>> {
    let mut iv = [0u8; 12];
    rng_gen(&mut iv)?;

    let ub_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)?;
    let nonce = Nonce::assume_unique_for_key(iv);
    let nonce_seq = OneNonceSequence::new(nonce);

    let mut s_key = aead::SealingKey::new(ub_key, nonce_seq);
    s_key.seal_in_place_append_tag(Aad::empty(), &mut msg)?;

    Ok(msg)
}

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


// TODO: User's Signature Verification

// TODO: Enclave's signature generation
