//! This module contains enclave specific cryptographic logics.

use sgx_types::sgx_report_data_t;
use std::prelude::v1::Vec;
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM};
use secp256k1::{self, Message, Signature, SecretKey, PublicKey,
    util::SECRET_KEY_SIZE,
};
use anonify_common::{Keccak256, IV_SIZE};
use anonify_app_preluder::{CIPHERTEXT_SIZE, Ciphertext};
use crate::error::Result;

lazy_static! {
    pub static ref SYMMETRIC_KEY: SymmetricKey = SymmetricKey::new_rand().unwrap();
}

/// The size of the symmetric 256 bit key we use for encryption in bytes.
const SYMMETRIC_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 32;
const ADDRESS_SIZE: usize = 20;
const FILLED_REPORT_DATA_SIZE: usize = ADDRESS_SIZE + NONCE_SIZE;
const REPORT_DATA_SIZE: usize = 64;

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

        Ok(Ciphertext::from_bytes(&data))
    }

    /// Decryption with AES-256-GCM.
    pub fn decrypt_aes_256_gcm(&self, cipheriv: Ciphertext) -> Result<Vec<u8>> {
        let ub_key = UnboundKey::new(&AES_256_GCM, &self.as_bytes())?;
        let (ciphertext, iv) = cipheriv.as_bytes().split_at(*CIPHERTEXT_SIZE - IV_SIZE);

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

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let msg = Message::parse_slice(msg)?;
        let sig = secp256k1::sign(&msg, &self.secret)?;
        Ok(sig.0)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secret)
    }

    /// Generate a value of REPORTDATA field in REPORT struct.
    /// REPORTDATA consists of a compressed secp256k1 public key and nonce.
    /// The public key is used for verifying signature on-chain to attest enclave's execution w/o a whole REPORT data,
    /// because this enclave identity key is binding to enclave's code.
    /// The nonce is used for preventing from replay attacks.
    /// 20bytes: address
    /// 32bytes: nonce
    /// 12bytes: zero padding
    pub fn report_data(&self) -> Result<sgx_report_data_t> {
        let mut report_data = [0u8; REPORT_DATA_SIZE];
        report_data[..ADDRESS_SIZE].copy_from_slice(&self.address()[..]);
        report_data[ADDRESS_SIZE..FILLED_REPORT_DATA_SIZE].copy_from_slice(&&self.nonce[..]);

        Ok(sgx_report_data_t {
            d: report_data
        })
    }

    fn address(&self) -> [u8; ADDRESS_SIZE] {
        let pubkey = &self.public_key().serialize();
        let address = &pubkey.keccak256()[12..];
        assert_eq!(address.len(), ADDRESS_SIZE);
        let mut res = [0u8; ADDRESS_SIZE];
        res.copy_from_slice(address);
        res
    }
}
