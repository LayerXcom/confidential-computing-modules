use super::{
    ecies::{AES_256_GCM_KEY_SIZE, AES_256_GCM_NONCE_SIZE},
    hmac::HmacKey,
};
use anyhow::{anyhow, Result};
use ring::{self, hkdf::KeyType};
use codec::Encode;

const ANONIFY_PREFIX: &[u8] = b"anonify";

#[derive(Debug, Encode)]
struct HkdfLabel<'a> {
    length: u16,
    label: &'a [u8],
    context: &'a [u8],
}

/// An implementation of HKDF-extract.
#[allow(dead_code)]
pub fn extract(salt: &HmacKey, secret: &[u8]) -> HmacKey {
    let prk = salt.sign(secret);
    HmacKey::from(prk)
}

pub fn expand_label(
    secret: &HmacKey,
    label_info: &[u8],
    context: &[u8],
    out_buf: &mut [u8],
) -> Result<()> {
    assert!(label_info.len() <= 255 - ANONIFY_PREFIX.len());
    assert!(out_buf.len() <= std::u16::MAX as usize);

    let mut full_label_info = [0u8; 255];
    full_label_info[0..ANONIFY_PREFIX.len()].copy_from_slice(ANONIFY_PREFIX);
    full_label_info[ANONIFY_PREFIX.len()..ANONIFY_PREFIX.len() + label_info.len()]
        .copy_from_slice(label_info);
    let full_label_info_slice = &full_label_info[0..ANONIFY_PREFIX.len() + label_info.len()];

    let label = HkdfLabel {
        length: out_buf.len() as u16,
        label: &full_label_info_slice,
        context,
    };

    expand(secret, &label, out_buf, ring::hkdf::HKDF_SHA256)
}

pub fn expand<E: Encode, L: KeyType>(
    salt: &HmacKey,
    info: &E,
    out_buf: &mut [u8],
    key_type: L,
) -> Result<()> {
    let encoded_info = info.encode();

    ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &salt.as_bytes())
        .expand(&[&encoded_info], key_type)
        .map_err(|e| anyhow!("{:?}", e))?
        .fill(out_buf)
        .map_err(|e| anyhow!("{:?}", e))
}

pub struct Aes256GcmNonce;

impl KeyType for Aes256GcmNonce {
    fn len(&self) -> usize {
        AES_256_GCM_NONCE_SIZE
    }
}

pub struct Aes256GcmKey;

impl KeyType for Aes256GcmKey {
    fn len(&self) -> usize {
        AES_256_GCM_KEY_SIZE
    }
}
