//! Secrets for key schedule
//! path_secret
//! -> node_secret
//! -> update_secret
//! -> app_secret
//! -> app_keychain

use std::vec::Vec;
use super::{
    SHA256_OUTPUT_LEN, hkdf,
    dh::{DhPrivateKey, DhPubKey},
    hmac::HmacKey,
    CryptoRng,
};
use crate::handshake::AccessKey;
use frame_common::crypto::sgx_rand_assign;
use anyhow::Result;
use codec::Encode;
use sgx_tseal::SgxSealedData;
use sgx_types::sgx_attributes_t;

const KEYPOLICY_MRENCLAVE: u16 = 0x0001;

#[derive(Debug, Clone)]
pub struct GroupEpochSecret(Vec<u8>);

impl From<Vec<u8>> for GroupEpochSecret {
    fn from(vec: Vec<u8>) -> Self {
        GroupEpochSecret(vec.into())
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
        NodeSecret(vec.into())
    }
}

impl From<&[u8]> for NodeSecret {
    fn from(bytes: &[u8]) -> Self {
        NodeSecret(bytes.into())
    }
}


#[derive(Debug, Clone, Copy)]
pub struct PathSecret(HmacKey);

unsafe impl sgx_types::marker::ContiguousMemory for PathSecret {}

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

        Ok((node_public_key, node_private_key, node_secret, parent_path_secret))
    }

    pub fn new_from_random_sgx() -> PathSecret {
        let mut buf = vec![0u8; SHA256_OUTPUT_LEN];
        sgx_rand_assign(&mut buf[..]).unwrap();
        PathSecret::from(buf)
    }

    pub fn new_from_random<R: CryptoRng>(csprng: &mut R) -> PathSecret {
        let key = HmacKey::new_from_random(csprng);
        PathSecret(key)
    }

    pub fn derive_next(self, access_key: AccessKey) -> Result<PathSecret> {
        let prk = HmacKey::from(self);
        let mut path_secret_buf = vec![0u8; SHA256_OUTPUT_LEN];
        hkdf::expand_label(&prk, b"next", &access_key.encode(), &mut path_secret_buf)?;

        Ok(PathSecret::from(path_secret_buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn seal(&self) -> Result<SgxSealedData<Self>> {
        let additional = [0u8; 0]; // todo: epoch
        let attribute_mask = sgx_attributes_t { flags: 0xffff_ffff_ffff_fff3, xfrm: 0 };

        SgxSealedData::<Self>::seal_data_ex(
            KEYPOLICY_MRENCLAVE,
            attribute_mask,
            0, //misc mask
            &additional,
            &self
        )
    }
}
