use std::vec::Vec;
use secp256k1::{PublicKey, SecretKey};

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
