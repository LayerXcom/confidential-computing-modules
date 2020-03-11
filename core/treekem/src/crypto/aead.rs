use ring::aead::{Nonce, NonceSequence, OpeningKey, SealingKey, AES_128_GCM, BoundKey, UnboundKey};
use anyhow::{Result, ensure};

pub const AES_128_GCM_KEY_SIZE: usize = 128 / 8;
pub const AES_128_GCM_TAG_SIZE: usize = 128 / 8;
pub const AES_128_GCM_NONCE_SIZE: usize = 96 / 8;

/// A sequences of unique nonces.
/// See: https://briansmith.org/rustdoc/ring/aead/trait.NonceSequence.html
pub struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    pub fn new(nonce: Nonce) -> Self {
        OneNonceSequence(Some(nonce))
    }
}

impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified).into()
    }
}
