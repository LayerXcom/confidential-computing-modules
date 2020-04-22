use std::vec::Vec;
use secp256k1::{PublicKey, SecretKey, util::{SECRET_KEY_SIZE, COMPRESSED_PUBLIC_KEY_SIZE}};
use anonify_common::sgx_rand_assign;
use anyhow::{anyhow, Result};
use codec::{Encode, Decode, Input, Error};
use super::{
    CryptoRng, hkdf,
    hmac::HmacKey,
};

#[derive(Debug, Clone)]
pub struct DhPrivateKey(SecretKey);

impl Encode for DhPrivateKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.serialize().using_encoded(f)
    }

    fn size_hint(&self) -> usize {
        SECRET_KEY_SIZE
    }
}

impl Decode for DhPrivateKey {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        let buf = <[u8; 32]>::decode(value)?;
        let privkey = SecretKey::parse(&buf).unwrap();
        Ok(DhPrivateKey(privkey))
    }
}

impl DhPrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::parse_slice(bytes)
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(DhPrivateKey(secret_key))
    }

    pub fn from_random() -> Result<Self> {
        let secret = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            sgx_rand_assign(&mut ret)?;

            match SecretKey::parse(&ret) {
                Ok(key) => break key,
                Err(_) => (),
            }
        };

        Ok(DhPrivateKey(secret))
    }
}

#[derive(Debug, Clone)]
pub struct DhPubKey(PublicKey);

impl Encode for DhPubKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.serialize_compressed().using_encoded(f)
    }

    fn size_hint(&self) -> usize {
        COMPRESSED_PUBLIC_KEY_SIZE
    }
}

impl Decode for DhPubKey {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        let buf = <[u8; 33]>::decode(value)?;
        let pubkey = PublicKey::parse_compressed(&buf).unwrap();
        Ok(DhPubKey(pubkey))
    }
}

impl DhPubKey {
    pub fn from_private_key(private_key: &DhPrivateKey) -> Self {
        DhPubKey(PublicKey::from_secret_key(&private_key.0))
    }
}

pub fn encapsulate(ephemeral_privkey: &DhPrivateKey, pubkey: &DhPubKey) -> Result<[u8; 32]> {
    let shared_point = diffie_hellman(ephemeral_privkey, pubkey)?;
    let ephemeral_pubkey = PublicKey::from_secret_key(&ephemeral_privkey.0);

    gen_out_buf(&ephemeral_pubkey, &shared_point)
}

pub fn decapsulate(privkey: &DhPrivateKey, ephemeral_pubkey: &DhPubKey) -> Result<[u8; 32]> {
    let shared_point = diffie_hellman(privkey, ephemeral_pubkey)?;

    gen_out_buf(&ephemeral_pubkey.0, &shared_point)
}


fn diffie_hellman(
    privkey: &DhPrivateKey,
    pubkey: &DhPubKey,
) -> Result<DhPubKey> {
    let mut shared_point = pubkey.clone();
    shared_point.0
        .tweak_mul_assign(&privkey.0)
        .map_err(|e| anyhow!("error: {:?}", e))?;

    Ok(shared_point)
}

fn gen_out_buf(pubkey: &PublicKey, shared_point: &DhPubKey) -> Result<[u8; 32]> {
    let mut master = Vec::with_capacity(COMPRESSED_PUBLIC_KEY_SIZE * 2);
    master.extend(pubkey.serialize_compressed().iter());
    master.extend(shared_point.0.serialize_compressed().iter());

    let mut out_buf = [0u8; 32];
    hkdf::expand(&HmacKey::from(master), b"dh", &mut out_buf, hkdf::Aes256GcmKey)?;
    Ok(out_buf)
}
