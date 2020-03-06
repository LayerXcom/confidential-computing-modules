use crate::crypto::DhPubKey;

// TODO: Does need signature over the group's history?
#[derive(Clone, Debug)]
pub struct Handshake {
    prior_epoch: u32,
    op: GroupOperation,
}

#[derive(Debug, Clone)]
pub enum GroupOperation {
    Add(GroupAdd),
}

#[derive(Debug, Clone)]
pub struct GroupAdd {
    /// Indicates where to add the new member.
    roster_index: u32,
    pub_key: DhPubKey,
}

impl GroupAdd {
    pub fn new(roster_index: u32, pub_key: DhPubKey) -> Self {
        GroupAdd { roster_index, pub_key }
    }
}
