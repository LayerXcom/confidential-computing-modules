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
struct GroupAdd {
    /// Indicates where to add the new member.
    roster_index: u32,
    pub_key: DhPubKey,
}
