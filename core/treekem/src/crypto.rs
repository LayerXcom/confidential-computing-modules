use secp256k1::{PublicKey;

#[derive(Debug, Clone)]
pub struct DhPubKey(PublicKey);

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
