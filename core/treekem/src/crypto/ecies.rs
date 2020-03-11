use std::vec::Vec;
use super::{
    dh::{DhPubKey, DhPrivateKey},
    aead::{Aes128GcmKey, AES_128_GCM_KEY_SIZE, AES_128_GCM_NONCE_SIZE, AES_128_GCM_TAG_SIZE},
    secrets::HmacKey,
    hkdf,
    CryptoRng,
};
use ring::aead::{Nonce, NonceSequence};
use anyhow::Result;
use codec::Encode;

#[derive(Debug, Clone)]
pub struct EciesCiphertext {
    ephemeral_public_key: DhPubKey,
    ciphertext: Vec<u8>,
}

impl EciesCiphertext {
    pub fn encrypt(
        pub_key: &DhPubKey,
        mut plaintext: Vec<u8>,
    ) -> Result<Self> {
        let mut my_ephemeral_secret = DhPrivateKey::from_random()?;

        let tagged_plaintext_size = plaintext
            .len()
            .checked_add(AES_128_GCM_TAG_SIZE)
            .expect("plaintext is too large to be encrypted.");
        plaintext.resize(tagged_plaintext_size, 0u8);

        let my_ephemeral_pub_key = DhPubKey::from_private_key(&my_ephemeral_secret);



        unimplemented!();
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

fn derive_ecies_key_nonce<N: NonceSequence>(shared_secret_bytes: &[u8]) -> (Aes128GcmKey<N>, Nonce) {
    let key_label = EciesLabel::new(b"key", AES_128_GCM_KEY_SIZE as u16);
    let nonce_label = EciesLabel::new(b"nonce", AES_128_GCM_NONCE_SIZE as u16);

    unimplemented!();
}
