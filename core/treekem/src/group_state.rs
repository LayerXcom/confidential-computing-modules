use crate::crypto::{CryptoRng, HmacKey, DhPubKey, GroupEpochSecret, AppSecret, UpdateSecret, SHA256_OUTPUT_LEN};
use crate::application::AppKeyChain;
use crate::handshake::{GroupAdd, GroupOperation, Handshake};
use crate::ratchet_tree::{RatchetTree, PathSecret};
use anyhow::{Result, anyhow};

/// Process the received handshake from a global ledger.
pub trait HandshakeApplier: Sized {
    fn apply_handshake(&self, handshake: &Handshake) -> Result<(GroupState, AppKeyChain)>;
}

pub trait AddOperator: Sized {
    fn create_add_handshake(
        &self,
        new_roster_index: u32,
        pub_key: DhPubKey,
    ) -> Result<(Handshake, GroupState, AppKeyChain)>;
}

pub trait UpdateOperator: Sized {
    fn create_update_handshake<R: CryptoRng>(
        &self,
        new_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<(Handshake, GroupState, AppKeyChain)>;
}

#[derive(Clone, Debug)]
pub struct GroupState {
    /// The current version of the group key
    epoch: u32,
    my_roster_index: Option<u32>,
    tree: RatchetTree,
    /// The initial secret used to derive app_secret.
    /// It works as a salt of HKDF.
    init_secret: HmacKey,
}

impl HandshakeApplier for GroupState {
    fn apply_handshake(&self, handshake: &Handshake) -> Result<(GroupState, AppKeyChain)> {
        if handshake.prior_epoch != self.epoch {
            return Err(anyhow!("Handshake's prior epoch isn't the current epoch."));
        }

        let sender_tree_idx = RatchetTree::roster_idx_to_tree_idx(handshake.roster_index())?;
        if sender_tree_idx > self.tree.size() {
            return Err(anyhow!("Handshake's roster index is out of range."));
        }

        let mut new_group_state = self.clone();
        new_group_state.increment_epoch()?;

        let new_group_epoch_secret = match handshake.op {
            GroupOperation::Add(ref add) => new_group_state.process_add_op(add)?
        };



        unimplemented!();
    }
}

impl AddOperator for GroupState {
    fn create_add_handshake(
        &self,
        new_roster_index: u32,
        pub_key: DhPubKey,
    ) -> Result<(Handshake, GroupState, AppKeyChain)> {
        let (new_group_state, app_key_chain, add_op) =
            self.update_by_add_op(new_roster_index, pub_key)?;
        let prior_epoch = self.epoch;
        let handshake = new_group_state.create_handshake(prior_epoch, add_op)?;

        Ok((handshake, new_group_state, app_key_chain))
    }
}

impl UpdateOperator for GroupState {
    fn create_update_handshake<R: CryptoRng>(
        &self,
        new_path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<(Handshake, GroupState, AppKeyChain)> {
        unimplemented!();
    }
}

impl GroupState {
    fn update_by_add_op(
        &self,
        new_roster_index: u32,
        pub_key: DhPubKey,
    ) -> Result<(GroupState, AppKeyChain, GroupOperation)> {
        let mut new_group_state = self.clone();
        let add_op = GroupAdd::new(new_roster_index, pub_key);
        let update_secret = new_group_state.process_add_op(&add_op)?;

        new_group_state.increment_epoch()?;
        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        Ok((new_group_state, app_key_chain, GroupOperation::Add(add_op)))
    }

    fn create_handshake(
        &self,
        prior_epoch: u32,
        op: GroupOperation,
    ) -> Result<Handshake> {
        unimplemented!();
    }

    /// Add a new member to group state.
    fn process_add_op(&mut self, add: &GroupAdd) -> Result<UpdateSecret> {
        let add_roster_index = add.roster_index;
        if add_roster_index as usize > self.tree.size() {
            return Err(anyhow!("Invalid roster index in add operation."));
        }

        let tree_index = RatchetTree::roster_idx_to_tree_idx(add_roster_index)?;


        Ok(UpdateSecret::from_zeros(SHA256_OUTPUT_LEN))
    }

    fn increment_epoch(&mut self) -> Result<()> {
        let new_epoch = self.epoch
            .checked_add(1)
            .ok_or(anyhow!("Cannot increment epoch past its maximum"))?;
        self.epoch = new_epoch;

        Ok(())
    }

    /// Set the next generation of Group Epoch Secret.
    fn update_epoch_secret(
        &mut self,
        update_secret: &UpdateSecret
    ) -> Result<AppSecret> {
        unimplemented!();
    }
}
