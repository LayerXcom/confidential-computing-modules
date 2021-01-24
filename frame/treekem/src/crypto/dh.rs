use super::{hkdf, hmac::HmacKey};
use crate::local_anyhow::{anyhow, Result};
use crate::local_secp256k1::{PublicKey, SecretKey};
use crate::localstd::{fmt, vec::Vec};
#[cfg(feature = "std")]
use crate::serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use frame_common::crypto::rand_assign;

const SECRET_KEY_SIZE: usize = 32;
const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DhPrivateKey(SecretKey);

impl DhPrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::parse_slice(bytes).map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(DhPrivateKey(secret_key))
    }

    pub fn from_random() -> Result<Self> {
        let secret = loop {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            rand_assign(&mut ret)?;

            if let Ok(key) = SecretKey::parse(&ret) {
                break key;
            }
        };

        Ok(DhPrivateKey(secret))
    }
}

impl Serialize for DhPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("DhPrivateKey", &self.0.serialize()[..])
    }
}

impl<'de> de::Deserialize<'de> for DhPrivateKey {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Copy, Clone, Debug)]
        struct PubKeyVisitor;

        impl<'de> Visitor<'de> for PubKeyVisitor {
            type Value = DhPrivateKey;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bytes of deserializable DhPrivateKey")
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut vec: Vec<u8> = Vec::new();
                while let Some(elem) = visitor.next_element()? {
                    vec.push(elem);
                }

                let pk = SecretKey::parse_slice(&vec[..]).map_err(|e| de::Error::custom(e))?;
                Ok(DhPrivateKey(pk))
            }

            fn visit_newtype_struct<D>(self, de: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                de.deserialize_bytes(PubKeyVisitor)
            }
        }

        de.deserialize_newtype_struct("DhPrivateKey", PubKeyVisitor)
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct DhPubKey(PublicKey);

#[cfg(feature = "sgx")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhPubKey(PublicKey);

impl Default for DhPubKey {
    fn default() -> Self {
        let secret_key = SecretKey::default();
        DhPubKey(PublicKey::from_secret_key(&secret_key))
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

fn diffie_hellman(privkey: &DhPrivateKey, pubkey: &DhPubKey) -> Result<DhPubKey> {
    let mut shared_point = pubkey.clone();
    shared_point
        .0
        .tweak_mul_assign(&privkey.0)
        .map_err(|e| anyhow!("error: {:?}", e))?;

    Ok(shared_point)
}

fn gen_out_buf(pubkey: &PublicKey, shared_point: &DhPubKey) -> Result<[u8; 32]> {
    let mut master = Vec::with_capacity(COMPRESSED_PUBLIC_KEY_SIZE * 2);
    master.extend(pubkey.serialize_compressed().iter());
    master.extend(shared_point.0.serialize_compressed().iter());

    let mut out_buf = [0u8; 32];
    hkdf::expand(
        &HmacKey::from(master),
        b"dh",
        &mut out_buf,
        hkdf::Aes256GcmKey,
    )?;
    Ok(out_buf)
}
