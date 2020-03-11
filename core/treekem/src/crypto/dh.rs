use secp256k1::{PublicKey, SecretKey};
use anyhow::{anyhow, Result};
use super::CryptoRng;

#[derive(Debug, Clone)]
pub struct DhPrivateKey(SecretKey);

impl DhPrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::parse_slice(bytes)
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(DhPrivateKey(secret_key))
    }

    pub fn from_random<R: rand::Rng>(csprng: &mut R) -> Self {
        DhPrivateKey(SecretKey::random(csprng))
    }
}

#[derive(Debug, Clone)]
pub struct DhPubKey(PublicKey);

impl DhPubKey {
    pub fn from_private_key(private_key: &DhPrivateKey) -> Self {
        DhPubKey(PublicKey::from_secret_key(&private_key.0))
    }
}
