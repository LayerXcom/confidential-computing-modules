use super::hmac::HmacKey;
use anyhow::Result;
use codec::Encode;

const ANONIFY_PREFIX: &[u8] = b"anonif";

#[derive(Debug, Encode)]
struct HkdfLabel<'a> {
    length: u16,
    label: &'a [u8],
    context: &'a [u8],
}

/// An implementation of HKDF-extract.
pub fn extract(salt: &HmacKey, secret: &[u8]) -> HmacKey {
    unimplemented!();
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

    expand(secret, &label, out_buf)
}

pub fn expand<E: Encode>(
    salt: &HmacKey,
    info: &E,
    out_buf: &mut [u8],
) -> Result<()> {
    let encoded_info = info.encode();

    ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &salt.as_bytes())
        .expand(&[&encoded_info], ring::hkdf::HKDF_SHA256)?
        .fill(out_buf)
        .map_err(Into::into)
}
