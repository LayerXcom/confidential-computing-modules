use crate::crypto::DhPubKey;
use crate::handshake::{GroupAdd, GroupOperation, Handshake};
use anyhow::Result;

#[derive(Clone, Debug)]
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
        &self,
        new_roster_index: u32,
        pub_key: DhPubKey,
    ) {
        let mut new_group_state = self.clone();
        let add_op = GroupAdd::new(new_roster_index, pub_key);
        let update_

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
