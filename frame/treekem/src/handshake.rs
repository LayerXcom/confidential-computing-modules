use crate::application::AppKeyChain;
use crate::crypto::{
    dh::DhPubKey, ecies::EciesCiphertext, hash::hash_encodable, secrets::PathSecret, CryptoRng,
};
use anyhow::Result;
use codec::{Decode, Encode};
use frame_common::crypto::ExportPathSecret;
use ring::digest::Digest;
use std::collections::HashMap;
use std::string::String;
use std::sync::{Arc, SgxRwLock};
use std::vec::Vec;

/// A handshake operates sharing a group key to each member.
pub trait Handshake: Sized {
    /// Create a handshake to broadcast other members.
    fn create_handshake(
        &self,
        source: &PathSecretSource,
    ) -> Result<(HandshakeParams, ExportPathSecret)>;

    /// Process a received handshake from other members.
    fn process_handshake<F>(
        &mut self,
        handshake: &HandshakeParams,
        source: &PathSecretSource,
        max_roster_idx: u32,
        req_path_secret_fn: F,
    ) -> Result<AppKeyChain>
    where
        F: FnOnce(&[u8]) -> Result<ExportPathSecret>;
}

// TODO: Does need signature over the group's history?
/// This `Handshake` is sent to global ledger.
#[derive(Clone, Debug, Encode, Decode)]
pub struct HandshakeParams {
    /// This is equal to the epoch of the current groupstate
    /// at the time of receicing and applying the handshake.
    prior_epoch: u32,
    roster_idx: u32,
    path: DirectPathMsg,
}

impl HandshakeParams {
    pub fn new(prior_epoch: u32, roster_idx: u32, path: DirectPathMsg) -> Self {
        HandshakeParams {
            prior_epoch,
            roster_idx,
            path,
        }
    }

    pub fn hash(&self) -> Digest {
        hash_encodable(&self)
    }

    pub fn prior_epoch(&self) -> u32 {
        self.prior_epoch
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn path(&self) -> &DirectPathMsg {
        &self.path
    }
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
        DirectPathNodeMsg {
            public_key,
            node_secrets,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PathSecretSource {
    Local,
    Remote(String),
    /// just for test use to derive new path secret depending on current path secret.
    LocalTest(CurrentPathSecret),
    LocalTestKV(PathSecretKVS),
}

#[derive(Debug, Clone)]
pub struct PathSecretKVS(HashMap<AccessKey, PathSecret>);

#[derive(Encode, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct AccessKey {
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
        let key = AccessKey { roster_idx, epoch };
        self.0.get(&key)
    }

    pub fn insert_random_path_secret<R: CryptoRng>(
        &mut self,
        roster_idx: u32,
        epoch: u32,
        csprng: &mut R,
    ) {
        let key = AccessKey { roster_idx, epoch };
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
