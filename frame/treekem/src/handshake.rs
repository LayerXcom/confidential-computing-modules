use std::vec::Vec;
use std::collections::HashMap;
use std::string::String;
use std::sync::{SgxRwLock, Arc};
use crate::application::AppKeyChain;
use crate::crypto::{
    CryptoRng,
    dh::DhPubKey,
    ecies::EciesCiphertext,
    secrets::PathSecret,
};
use anyhow::Result;
use codec::{Encode, Decode};

/// A handshake operates sharing a group key to each member.
pub trait Handshake: Sized {
    /// Create a handshake to broadcast other members.
    fn create_handshake(&self, req: &PathSecretRequest) -> Result<(HandshakeParams, PathSecret)>;

    /// Process a received handshake from other members.
    fn process_handshake(
        &mut self,
        handshake: &HandshakeParams,
        req: &PathSecretRequest,
        max_roster_idx: u32
    ) -> Result<AppKeyChain>;
}

// TODO: Does need signature over the group's history?
/// This `Handshake` is sent to global ledger.
#[derive(Clone, Debug, Encode, Decode)]
pub struct HandshakeParams {
    /// This is equal to the epoch of the current groupstate
    /// at the time of receicing and applying the handshake.
    pub prior_epoch: u32,
    pub roster_idx: u32,
    pub path: DirectPathMsg,
}

/// Encrypted direct path
#[derive(Debug, Clone, Encode, Decode)]
pub struct DirectPathMsg {
    pub node_msgs: Vec<DirectPathNodeMsg>,
}

impl DirectPathMsg {
    pub fn new(node_msgs: Vec<DirectPathNodeMsg>) -> Self {
        DirectPathMsg { node_msgs }
    }
}

/// Containes a direct path node's public key and encrypted secrets
#[derive(Debug, Clone, Encode, Decode)]
pub struct DirectPathNodeMsg {
    pub public_key: DhPubKey,
    pub node_secrets: Vec<EciesCiphertext>,
}

impl DirectPathNodeMsg {
    pub fn new(public_key: DhPubKey, node_secrets: Vec<EciesCiphertext>) -> Self {
        DirectPathNodeMsg { public_key, node_secrets }
    }
}

#[derive(Debug, Clone)]
pub enum PathSecretRequest {
    Local(PathSecretKVS),
    Remote(String),
    /// just for test use to derive new path secret depending on current path secret.
    LocalTest(CurrentPathSecret),
}

#[derive(Debug, Clone)]
pub struct PathSecretKVS(HashMap<AccessKey, PathSecret>);

#[derive(Encode, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct AccessKey{
    roster_idx: u32,
    epoch: u32,
}

impl AccessKey {
    pub fn new(roster_idx: u32, epoch: u32) -> Self {
        AccessKey { roster_idx, epoch }
    }
}

impl PathSecretKVS {
    pub fn new() -> Self {
        let map: HashMap<AccessKey, PathSecret> = HashMap::new();
        PathSecretKVS(map)
    }

    pub fn get(&self, roster_idx: u32, epoch: u32) -> Option<&PathSecret> {
        let key = AccessKey{roster_idx, epoch};
        self.0.get(&key)
    }

    pub fn insert_random_path_secret<R: CryptoRng>(&mut self, roster_idx: u32, epoch: u32, csprng: &mut R) {
        let key = AccessKey{roster_idx, epoch};
        let value = PathSecret::new_from_random(csprng);
        self.0.insert(key, value);
    }
}

#[derive(Debug, Clone)]
pub struct CurrentPathSecret(pub Arc<SgxRwLock<PathSecret>>);

impl CurrentPathSecret {
    pub fn new_from_random() -> Self {
        let path_secret = PathSecret::new_from_random_sgx();
        CurrentPathSecret(Arc::new(SgxRwLock::new(path_secret)))
    }
}
