use std::vec::Vec;
use crate::crypto::{
    dh::DhPubKey,
    ecies::EciesCiphertext
};

// TODO: Does need signature over the group's history?
/// This `Handshake` is sent to global ledger.
#[derive(Clone, Debug)]
pub struct Handshake {
    /// This is equal to the epoch of the current groupstate
    /// at the time of receicing and applying the handshake.
    pub prior_epoch: u32,
    /// The performing operation
    pub op: GroupOperation,
}

impl Handshake {
    pub fn new(prior_epoch: u32, op: GroupOperation) -> Self {
        Handshake { prior_epoch, op }
    }

    pub fn roster_index(&self) -> u32 {
        match self.op {
            GroupOperation::Add(ref add) => add.roster_index,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum GroupOperation {
    Add(GroupAdd),
    Update(GroupUpdate),
}

#[derive(Debug, Clone)]
pub struct GroupAdd {
    /// Indicates where to add the new member.
    pub roster_index: u32,
    pub public_key: DhPubKey,
}

impl GroupAdd {
    pub fn new(roster_index: u32, public_key: DhPubKey) -> Self {
        GroupAdd { roster_index, public_key }
    }
}

#[derive(Debug, Clone)]
pub struct GroupUpdate {
    pub path: DirectPathMsg,
}

impl GroupUpdate {
    pub fn new(path: DirectPathMsg) -> Self {
        GroupUpdate { path }
    }
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

/// Containes a direc
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
