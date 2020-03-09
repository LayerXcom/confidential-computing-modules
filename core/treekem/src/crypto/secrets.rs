use std::vec::Vec;

#[derive(Debug, Clone)]
pub struct GroupEpochSecret(Vec<u8>);

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

pub struct UpdateSecret(Vec<u8>);

impl UpdateSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero(len: usize) -> Self {
        UpdateSecret(vec![0u8; len])
    }
}

#[derive(Debug, Clone)]
pub struct PathSecret(HmacKey);

impl From<PathSecret> for HmacKey {
    fn from(path: PathSecret) -> Self {
        path.0
    }
}

impl PathSecret {
    pub fn derive_node_values(&self) {
        
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
