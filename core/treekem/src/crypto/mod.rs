use secp256k1::{PublicKey, SecretKey};

pub mod hkdf;
pub mod secrets;

pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

pub trait CryptoRng: rand::RngCore + rand::CryptoRng {}
impl<T> CryptoRng for T
    where T: rand::RngCore + rand::CryptoRng {}

#[derive(Debug, Clone)]
pub struct DhPrivateKey(SecretKey);

#[derive(Debug, Clone)]
pub struct DhPubKey(PublicKey);

impl DhPubKey {
    pub fn from_private_key(private_key: &DhPrivateKey) -> Self {
        DhPubKey(PublicKey::from_secret_key(&private_key.0))
    }
}
