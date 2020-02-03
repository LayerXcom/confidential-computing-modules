//! This module containes enclave specific cryptographic logics.

use sgx_types::sgx_report_data_t;
use std::{
    prelude::v1::Vec,
    io::Read,
};
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM};
use secp256k1::{SecretKey, PublicKey, util::{
    SECRET_KEY_SIZE,
    COMPRESSED_PUBLIC_KEY_SIZE,
}};
use crate::error::Result;

lazy_static! {
    pub static ref SYMMETRIC_KEY: SymmetricKey = SymmetricKey::new_rand().unwrap();
}

/// The size of the symmetric 256 bit key we use for encryption in bytes.
const SYMMETRIC_KEY_SIZE: usize = 32;
/// The size of initialization vector for AES-256-GCM.
const IV_SIZE: usize = 12;
const NONCE_SIZE: usize = 31;
const REPORT_DATA_SIZE: usize = COMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE;

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
    pub fn encrypt_aes_256_gcm(&self, msg: Vec<u8>) -> Result<Ciphertext> {
        let mut iv = [0u8; IV_SIZE];
        sgx_rand_assign(&mut iv)?;

        let ub_key = UnboundKey::new(&AES_256_GCM, &self.as_bytes())?;
        let nonce = Nonce::assume_unique_for_key(iv);
        let nonce_seq = OneNonceSequence::new(nonce);

        let mut s_key = aead::SealingKey::new(ub_key, nonce_seq);
        let mut data = msg;
        s_key.seal_in_place_append_tag(Aad::empty(), &mut data)?;
        data.extend_from_slice(&iv);

        Ok(Ciphertext(data))
    }

    /// Decryption with AES-256-GCM.
    pub fn decrypt_aes_256_gcm(&self, cipheriv: Ciphertext) -> Result<Vec<u8>> {
        let ub_key = UnboundKey::new(&AES_256_GCM, &self.as_bytes())?;
        let (ciphertext, iv) = cipheriv.0.split_at(cipheriv.0.len() - IV_SIZE);

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

#[derive(Debug, Clone)]
pub struct Ciphertext(pub Vec<u8>);

impl Ciphertext {
    pub fn new(raw: Vec<u8>) -> Self {
        Ciphertext(raw)
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
pub struct Eik {
    secret: SecretKey,
    nonce: [u8; NONCE_SIZE],
}

impl Eik {
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

        Ok(Eik {
            secret,
            nonce,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secret)
    }

    /// Generate a value of REPORTDATA field in REPORT struct.
    /// REPORTDATA consists of a compressed secp256k1 public key and nonce.
    /// The public key is used for verifying signature on-chain to attest enclave's execution w/o a whole REPORT data,
    /// because this enclave identity key is binding to enclave's code.
    /// The nonce is used for prevenring from replay attacks.
    pub fn report_date(&self) -> sgx_report_data_t {
        let mut report_data = [0u8; REPORT_DATA_SIZE];
        let ser_pubkey = &self.public_key().serialize_compressed();
        report_data[..COMPRESSED_PUBLIC_KEY_SIZE].copy_from_slice(&ser_pubkey[..]);
        report_data[COMPRESSED_PUBLIC_KEY_SIZE..].copy_from_slice(&self.nonce[..]);

        sgx_report_data_t {
            d: report_data
        }
    }
}
