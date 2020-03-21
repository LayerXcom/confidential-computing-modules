use std::vec::Vec;
use crate::crypto::{
    dh::DhPubKey,
    ecies::EciesCiphertext
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
    // pub op: GroupOperation,
}

// #[derive(Debug, Clone)]
// pub enum GroupOperation {
//     Add(GroupAdd),
//     Update(GroupUpdate),
// }

// #[derive(Debug, Clone)]
// pub struct GroupAdd {
//     pub public_key: DhPubKey,
// }

// impl GroupAdd {
//     pub fn new(public_key: DhPubKey) -> Self {
//         GroupAdd { public_key }
//     }
// }

// #[derive(Debug, Clone)]
// pub struct GroupUpdate {
//     pub path: DirectPathMsg,
// }

// impl GroupUpdate {
//     pub fn new(path: DirectPathMsg) -> Self {
//         GroupUpdate { path }
//     }
// }

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
