use std::vec::Vec;
use secp256k1::{PublicKey, SecretKey};

pub mod hkdf;

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

#[derive(Debug, Clone)]
pub struct GroupEpochSecret(Vec<u8>);

#[derive(Debug, Clone)]
pub struct HmacKey(Vec<u8>);

impl HmacKey {
    pub fn zero(len: usize) -> Self {
        HmacKey(vec![0u8; len])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct AppSecret(HmacKey);

impl From<HmacKey> for AppSecret {
    fn from(key: HmacKey) -> Self {
        AppSecret(key)
    }
}

impl From<AppSecret> for HmacKey {
    fn from(secret: AppSecret) -> Self {
        secret.0
    }
}

/// A secret hat is unique to a member of the group.
#[derive(Debug, Clone)]
pub struct AppMemberSecret(HmacKey);

impl From<AppMemberSecret> for HmacKey {
    fn from(secret: AppMemberSecret) -> Self {
        secret.0
    }
}

pub struct UpdateSecret(Vec<u8>);

impl UpdateSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero(len: usize) -> Self {
        UpdateSecret(vec![0u8; len])
    }
}
