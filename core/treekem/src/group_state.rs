use crate::crypto::{DhPubKey, GroupEpochSecret, AppSecret};
use crate::application::AppKeyChain;
use crate::handshake::{GroupAdd, GroupOperation, Handshake};
use anyhow::{Result, anyhow};

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
    ) -> Result<(Handshake, GroupState, AppKeyChain)> {

        unimplemented!();
    }

    fn update_by_add_op(
        &self,
        new_roster_index: u32,
        pub_key: DhPubKey,
    ) -> Result<(GroupState, AppKeyChain, GroupOperation)> {
        let mut new_group_state = self.clone();
        let add_op = GroupAdd::new(new_roster_index, pub_key);
        let new_epoch_secret = new_group_state.process_add_op(&add_op)?;

        new_group_state.increment_epoch()?;
        let app_secret = new_group_state.update_epoch_secret(&new_epoch_secret)?;

        unimplemented!();
    }

    fn create_handshake(
        &self,
        prior_epoch: u32,
        op: GroupOperation,
    ) -> Result<Handshake> {
        unimplemented!();
    }

    fn process_add_op(&mut self, add: &GroupAdd) -> Result<GroupEpochSecret> {
        unimplemented!();
    }

    fn increment_epoch(&mut self) -> Result<()> {
        let new_epoch = self.epoch
            .checked_add(1)
            .ok_or(anyhow!("Cannot increment epoch past its maximum"))?;
        self.epoch = new_epoch;

        Ok(())
    }

    fn update_epoch_secret(
        &mut self,
        update_secret: &GroupEpochSecret
    ) -> Result<AppSecret> {
        unimplemented!();
    }
}
