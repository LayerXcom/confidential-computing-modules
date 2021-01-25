use super::{
    ecies::{AES_256_GCM_KEY_SIZE, AES_256_GCM_NONCE_SIZE},
    hash::hash_encodable,
    hmac::HmacKey,
    SHA256_OUTPUT_LEN,
};
use crate::bincode;
use crate::local_anyhow::{anyhow, Result};
use crate::local_ring::{self, hkdf::KeyType};
use crate::localstd;
use crate::serde::{Deserialize, Serialize};
use crate::serde_bytes;

const ANONIFY_PREFIX: &[u8] = b"anonify";

#[derive(Debug, Serialize)]
#[serde(crate = "crate::serde")]
struct HkdfLabel<'a> {
    length: u16,
    #[serde(with = "serde_bytes")]
    label: &'a [u8],
    #[serde(with = "serde_bytes")]
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
    assert!(out_buf.len() <= localstd::u16::MAX as usize);

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

    expand(secret, &label, out_buf, local_ring::hkdf::HKDF_SHA256)
}

pub fn expand<E: Serialize, L: KeyType>(
    salt: &HmacKey,
    info: &E,
    out_buf: &mut [u8],
    key_type: L,
) -> Result<()> {
    let encoded_info = bincode::serialize(&info)?;

    local_ring::hkdf::Prk::new_less_safe(local_ring::hkdf::HKDF_SHA256, &salt.as_bytes())
        .expand(&[&encoded_info], key_type)
        .map_err(|e| anyhow!("{:?}", e))?
        .fill(out_buf)
        .map_err(|e| anyhow!("{:?}", e))
}

/// Derive-Secret(Secret, Label, Context) =
///  HKDF-Expand-Label(Secret, Label, Hash(Context), Hash.length)
pub fn derive_secret<E: Serialize>(
    secret: &HmacKey,
    label_info: &[u8],
    context: &E,
) -> Result<HmacKey> {
    let key = {
        let hashed_ctx = hash_encodable(context);
        let mut key_buf = vec![0u8; SHA256_OUTPUT_LEN];
        expand_label(secret, label_info, hashed_ctx.as_ref(), &mut key_buf)?;
        HmacKey::from(key_buf)
    };
    Ok(key)
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
