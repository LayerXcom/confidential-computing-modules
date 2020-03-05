use crate::crypto::DhPubKey;
use crate::handshake::{GroupOperation, Handshake};
use anyhow::Result;

pub struct GroupState {

    /// The current version of the group key
    epoch: u32,

    my_roster_index: Option<u32>,
}

impl GroupState {
    pub fn apply_add_handshake(
        &self,
        roster_index: u32,
        pub_key: DhPubKey,
    ) {
        unimplemented!();
    }

    fn update_by_add_op(
        &self
    ) {
        unimplemented!();
    }

    fn create_handshake(
        &self,
        prior_epoch: u32,
        op: GroupOperation,
    ) -> Result<Handshake> {
        unimplemented!();
    }
}
