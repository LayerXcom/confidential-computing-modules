use std::vec::Vec;
use super::{
    dh::{DhPubKey, DhPrivateKey, diffie_hellman},
    aead::{OneNonceSequence, AES_128_GCM_KEY_SIZE, AES_128_GCM_NONCE_SIZE, AES_128_GCM_TAG_SIZE},
    secrets::HmacKey,
    hkdf,
    CryptoRng,
};
use ring::aead::{Nonce, NonceSequence, UnboundKey, BoundKey, OpeningKey, Aad, SealingKey, AES_256_GCM};
use anyhow::Result;
use codec::Encode;

#[derive(Debug, Clone)]
pub struct EciesCiphertext {
    ephemeral_public_key: DhPubKey,
    ciphertext: Vec<u8>,
}

impl EciesCiphertext {
    pub fn encrypt(
        others_pub_key: &DhPubKey,
        mut plaintext: Vec<u8>,
    ) -> Result<Self> {
        let mut my_ephemeral_secret = DhPrivateKey::from_random()?;

        let tagged_plaintext_size = plaintext
            .len()
            .checked_add(AES_128_GCM_TAG_SIZE)
            .expect("plaintext is too large to be encrypted.");
        plaintext.resize(tagged_plaintext_size, 0u8);

        let my_ephemeral_pub_key = DhPubKey::from_private_key(&my_ephemeral_secret);
        let shared_secret = diffie_hellman(&my_ephemeral_secret, &others_pub_key)?;
        let (ub_key, nonce_seq) = derive_ecies_key_nonce(&shared_secret)?;
        let mut sealing_key = SealingKey::new(ub_key, nonce_seq);
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut plaintext)?;

        let ciphertext = plaintext;

        Ok(EciesCiphertext {
            ephemeral_public_key: my_ephemeral_pub_key,
            ciphertext,
        })
    }
}

#[derive(Debug, Encode)]
struct EciesLabel {
    length: u16,
    label: Vec<u8>,
}

impl EciesLabel {
    pub fn new(label: &[u8], length: u16) -> Self {
        EciesLabel {
            length,
            label: [b"anonifyecies", label].concat(),
        }
    }
}

fn derive_ecies_key_nonce(
    shared_secret_bytes: &[u8],
) -> Result<(UnboundKey, OneNonceSequence)> {
    let key_label = EciesLabel::new(b"key", AES_128_GCM_KEY_SIZE as u16);
    let nonce_label = EciesLabel::new(b"nonce", AES_128_GCM_NONCE_SIZE as u16);

    let prk = HmacKey::from(shared_secret_bytes);
    let mut key_buf = [0u8; AES_128_GCM_KEY_SIZE];
    let mut nonce_buf = [0u8; AES_128_GCM_NONCE_SIZE];

    hkdf::expand(&prk, &key_label, &mut key_buf[..])?;
    hkdf::expand(&prk, &nonce_label, &mut nonce_buf[..])?;

    let ub_key = UnboundKey::new(&AES_256_GCM, &key_buf)?;
    let nonce = Nonce::assume_unique_for_key(nonce_buf);
    let nonce_seq = OneNonceSequence::new(nonce);

    Ok((ub_key, nonce_seq))
}
