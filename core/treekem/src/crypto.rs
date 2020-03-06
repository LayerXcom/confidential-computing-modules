use std::vec::Vec;
use secp256k1::{PublicKey, SecretKey};

pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

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

pub struct UpdateSecret(Vec<u8>);

impl UpdateSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_zeros(len: usize) -> Self {
        UpdateSecret(vec![0u8; len])
    }
}
