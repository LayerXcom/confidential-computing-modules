use std::vec::Vec;
use std::collections::HashMap;
use std::string::String;
use crate::crypto::{
    CryptoRng,
    dh::DhPubKey,
    ecies::EciesCiphertext,
    secrets::PathSecret,
};

// TODO: Does need signature over the group's history?
/// This `Handshake` is sent to global ledger.
#[derive(Clone, Debug)]
pub struct HandshakeParams {
    /// This is equal to the epoch of the current groupstate
    /// at the time of receicing and applying the handshake.
    pub prior_epoch: u32,
    pub roster_idx: u32,
    pub path: DirectPathMsg,
}

/// Encrypted direct path
#[derive(Debug, Clone)]
pub struct DirectPathMsg {
    pub node_msgs: Vec<DirectPathNodeMsg>,
}

impl DirectPathMsg {
    pub fn new(node_msgs: Vec<DirectPathNodeMsg>) -> Self {
        DirectPathMsg { node_msgs }
    }
}

/// Containes a direct path node's public key and encrypted secrets
#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
pub struct PathSecretKVS(HashMap<AccessKey, PathSecret>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct AccessKey{
    roster_idx: u32,
    epoch: u32,
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
