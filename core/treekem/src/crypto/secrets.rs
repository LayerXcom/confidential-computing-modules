use std::vec::Vec;
use super::{
    SHA256_OUTPUT_LEN, hkdf,
    dh::{DhPrivateKey, DhPubKey},
};
use anyhow::Result;

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
#[derive(Debug, Clone)]
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
        (self.0).0.as_mut_slice()
    }
}

pub struct UpdateSecret(Vec<u8>);

impl UpdateSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero(len: usize) -> Self {
        UpdateSecret(vec![0u8; len])
    }
}

/// node_secret[n] = HKDF-Expand-Label(path_secret[n], "node", "", Hash.Length)
#[derive(Debug, Clone)]
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


#[derive(Debug, Clone)]
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
        let new_path_secret = PathSecret::from(path_secret_buf);

        Ok((node_public_key, node_private_key, node_secret, new_path_secret))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct HmacKey(Vec<u8>);

impl HmacKey {
    pub fn zero(len: usize) -> Self {
        HmacKey(vec![0u8; len])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for HmacKey {
    fn from(vec: Vec<u8>) -> Self {
        HmacKey(vec)
    }
}

impl From<&[u8]> for HmacKey {
    fn from(bytes: &[u8]) -> Self {
        HmacKey(bytes.to_vec())
    }
}
