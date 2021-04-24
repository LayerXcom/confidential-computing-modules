//! Secrets for key schedule
//! path_secret
//! -> node_secret
//! -> update_secret
//! -> app_secret
//! -> app_keychain

use super::{
    dh::{DhPrivateKey, DhPubKey},
    hkdf,
    hmac::HmacKey,
    CryptoRng, SHA256_OUTPUT_LEN,
};
use crate::handshake::AccessKey;
use anyhow::{anyhow, Result};
use frame_common::crypto::rand_assign;
use frame_common::crypto::{ExportPathSecret, EXPORT_ID_SIZE, SEALED_DATA_SIZE};
use serde::{
    de::{self, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use sgx_tseal::SgxSealedData;
use sgx_types::sgx_sealed_data_t;
use std::{boxed::Box, fmt, vec::Vec};

#[derive(Debug, Clone)]
pub struct GroupEpochSecret(Vec<u8>);

impl From<Vec<u8>> for GroupEpochSecret {
    fn from(vec: Vec<u8>) -> Self {
        GroupEpochSecret(vec)
    }
}

impl From<&[u8]> for GroupEpochSecret {
    fn from(bytes: &[u8]) -> Self {
        GroupEpochSecret(bytes.into())
    }
}

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

/// A secret hat is unique to a member of the group.
#[derive(Debug, Clone, Default)]
pub struct AppMemberSecret(HmacKey);

impl From<Vec<u8>> for AppMemberSecret {
    fn from(vec: Vec<u8>) -> Self {
        AppMemberSecret(vec.into())
    }
}

impl From<&[u8]> for AppMemberSecret {
    fn from(bytes: &[u8]) -> Self {
        AppMemberSecret(bytes.into())
    }
}

impl From<AppMemberSecret> for HmacKey {
    fn from(secret: AppMemberSecret) -> Self {
        secret.0
    }
}

impl From<&AppMemberSecret> for HmacKey {
    fn from(secret: &AppMemberSecret) -> Self {
        secret.0.clone()
    }
}

impl AppMemberSecret {
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        (self.0).as_mut_bytes()
    }
}

#[derive(Debug, Clone, Default)]
pub struct UpdateSecret(Vec<u8>);

impl UpdateSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[allow(dead_code)]
    pub fn zero(len: usize) -> Self {
        UpdateSecret(vec![0u8; len])
    }
}

impl From<NodeSecret> for UpdateSecret {
    fn from(n: NodeSecret) -> Self {
        UpdateSecret(n.0)
    }
}

impl From<&UpdateSecret> for HmacKey {
    fn from(s: &UpdateSecret) -> Self {
        s.as_bytes().into()
    }
}

/// node_secret[n] = HKDF-Expand-Label(path_secret[n], "node", "", Hash.Length)
#[derive(Debug, Clone, Default)]
pub struct NodeSecret(Vec<u8>);

impl From<Vec<u8>> for NodeSecret {
    fn from(vec: Vec<u8>) -> Self {
        NodeSecret(vec)
    }
}

impl From<&[u8]> for NodeSecret {
    fn from(bytes: &[u8]) -> Self {
        NodeSecret(bytes.into())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathSecret(HmacKey);

impl From<PathSecret> for HmacKey {
    fn from(path: PathSecret) -> Self {
        path.0
    }
}

impl From<Vec<u8>> for PathSecret {
    fn from(vec: Vec<u8>) -> Self {
        PathSecret(vec.into())
    }
}

impl From<&[u8]> for PathSecret {
    fn from(bytes: &[u8]) -> Self {
        PathSecret(bytes.into())
    }
}

impl PathSecret {
    /// See sec 5.4.
    pub fn derive_node_values(self) -> Result<(DhPubKey, DhPrivateKey, NodeSecret, PathSecret)> {
        let prk = HmacKey::from(self);
        let mut node_secret_buf = vec![0u8; SHA256_OUTPUT_LEN];
        hkdf::expand_label(&prk, b"node", b"", &mut node_secret_buf)?;

        let mut path_secret_buf = vec![0u8; SHA256_OUTPUT_LEN];
        hkdf::expand_label(&prk, b"path", b"", &mut path_secret_buf)?;

        // TODO: Consider whether node_secret_buf is supposed to be hashed or not.
        let node_private_key = DhPrivateKey::from_bytes(&node_secret_buf)?;
        let node_public_key = DhPubKey::from_private_key(&node_private_key);

        let node_secret = NodeSecret::from(node_secret_buf);
        let parent_path_secret = PathSecret::from(path_secret_buf);

        Ok((
            node_public_key,
            node_private_key,
            node_secret,
            parent_path_secret,
        ))
    }

    pub fn new_from_random_sgx() -> PathSecret {
        let mut buf = vec![0u8; SHA256_OUTPUT_LEN];
        rand_assign(&mut buf[..]).unwrap();
        PathSecret::from(buf)
    }

    pub fn new_from_random<R: CryptoRng>(csprng: &mut R) -> PathSecret {
        let key = HmacKey::new_from_random(csprng);
        PathSecret(key)
    }

    pub fn derive_next(self, access_key: AccessKey) -> Result<PathSecret> {
        let prk = HmacKey::from(self);
        let mut path_secret_buf = vec![0u8; SHA256_OUTPUT_LEN];
        hkdf::expand_label(
            &prk,
            b"next",
            &bincode::serialize(&access_key)?,
            &mut path_secret_buf,
        )?;

        Ok(PathSecret::from(path_secret_buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn try_into_exporting(self, epoch: u32, id: &[u8]) -> Result<ExportPathSecret> {
        let encoded_sealed = UnsealedPathSecret::from(self).encoded_seal()?;
        let mut id_arr = [0u8; EXPORT_ID_SIZE];
        id_arr.copy_from_slice(&id[..]);

        Ok(ExportPathSecret::new(encoded_sealed, epoch, id_arr))
    }

    pub fn try_from_importing(imp_path_secret: ExportPathSecret) -> Result<Self> {
        let sealed_path_secret = SealedPathSecret::decode(&mut imp_path_secret.encoded_sealed())
            .map_err(|e| anyhow!("error: {:?}", e))?
            .unseal()?;

        Ok(sealed_path_secret.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnsealedPathSecret([u8; SHA256_OUTPUT_LEN]);

impl UnsealedPathSecret {
    pub fn encoded_seal(self) -> Result<Vec<u8>> {
        let additional = [0u8; 0];
        let sealed_data = SgxSealedData::<Self>::seal_data(&additional, &self)
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(SealedPathSecret::new(sealed_data).encode())
    }
}

unsafe impl sgx_types::marker::ContiguousMemory for UnsealedPathSecret {}

impl From<PathSecret> for UnsealedPathSecret {
    fn from(ps: PathSecret) -> Self {
        assert_eq!(ps.len(), SHA256_OUTPUT_LEN);
        let mut res = [0u8; SHA256_OUTPUT_LEN];
        res.copy_from_slice(ps.as_bytes());
        UnsealedPathSecret(res)
    }
}

impl From<UnsealedPathSecret> for PathSecret {
    fn from(ups: UnsealedPathSecret) -> Self {
        ups.0.as_ref().into()
    }
}

#[derive(Default, Clone)]
pub struct SealedPathSecret<'a>(SgxSealedData<'a, UnsealedPathSecret>);

impl<'a> SealedPathSecret<'a> {
    pub fn new(sealed_data: SgxSealedData<'a, UnsealedPathSecret>) -> Self {
        SealedPathSecret(sealed_data)
    }

    pub fn unseal(&self) -> Result<UnsealedPathSecret> {
        let unsealed_data = self
            .0
            .unseal_data()
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(*unsealed_data.get_decrypt_txt())
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    pub fn decode(bytes: &'a [u8]) -> std::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(bytes)
    }
}

impl Serialize for SealedPathSecret<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![0u8; SEALED_DATA_SIZE];
        unsafe {
            self.0.to_raw_sealed_data_t(
                bytes.as_mut_ptr() as *mut sgx_sealed_data_t,
                SEALED_DATA_SIZE as u32,
            );
        }

        let mut tup = serializer.serialize_tuple(SEALED_DATA_SIZE)?;
        for byte in bytes.iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl<'de> Deserialize<'de> for SealedPathSecret<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SealedPathSecretVisitor;

        impl<'de> de::Visitor<'de> for SealedPathSecretVisitor {
            type Value = SealedPathSecret<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a SealedPathSecret must be 32 bytes length")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut_v = &mut value.to_vec()[..];
                let sealed_data = unsafe {
                    SgxSealedData::<UnsealedPathSecret>::from_raw_sealed_data_t(
                        mut_v.as_mut_ptr() as *mut sgx_sealed_data_t,
                        SEALED_DATA_SIZE as u32,
                    )
                }
                .ok_or_else(|| {
                    E::custom(&"Fail SgxSealedData::<UnsealedPathSecret>::from_raw_sealed_data_t")
                })?;

                Ok(SealedPathSecret::new(sealed_data))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0u8; SEALED_DATA_SIZE];
                for i in 0..SEALED_DATA_SIZE {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(de::Error::invalid_length(i, &"32"))?;
                }

                let sealed_data = unsafe {
                    SgxSealedData::<UnsealedPathSecret>::from_raw_sealed_data_t(
                        bytes.as_mut_ptr() as *mut sgx_sealed_data_t,
                        SEALED_DATA_SIZE as u32,
                    )
                }
                .ok_or_else(|| {
                    de::Error::invalid_value(
                        Unexpected::Bytes(&bytes[..]),
                        &"Fail SgxSealedData::<UnsealedPathSecret>::from_raw_sealed_data_t",
                    )
                })?;

                Ok(SealedPathSecret::new(sealed_data))
            }
        }

        deserializer.deserialize_tuple(SEALED_DATA_SIZE, SealedPathSecretVisitor)
    }
}

impl fmt::Debug for SealedPathSecret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedPathSecret").finish()
    }
}

#[cfg(debug_assertions)]
pub(crate) mod tests {
    use super::*;
    use std::string::String;
    use test_utils::{runner::*, check_all_passed, run_tests};

    pub(crate) fn run_tests() -> bool {
        run_tests!(test_seal_unseal_path_secret,)
    }

    fn test_seal_unseal_path_secret() {
        let path_secret = PathSecret::new_from_random_sgx();
        let encoded_sealed_path_secret = UnsealedPathSecret::from(path_secret.clone())
            .encoded_seal()
            .unwrap();
        let sealed_path_secret =
            SealedPathSecret::decode(&mut &encoded_sealed_path_secret[..]).unwrap();
        let unsealed_path_secret = sealed_path_secret.unseal().unwrap();
        assert_eq!(path_secret, unsealed_path_secret.into());
    }
}
