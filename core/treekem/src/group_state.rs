use crate::crypto::{
    CryptoRng, SHA256_OUTPUT_LEN,
    dh::{DhPrivateKey, DhPubKey},
    secrets::{HmacKey, GroupEpochSecret, AppSecret, UpdateSecret, PathSecret},
};
use crate::application::AppKeyChain;
use crate::handshake::{GroupAdd, GroupOperation, Handshake};
use crate::ratchet_tree::{RatchetTree, RatchetTreeNode};
use anyhow::{Result, anyhow, ensure};

/// Process the received handshake from a global ledger.
pub trait HandshakeProcessor: Sized {
    fn process_handshake(&self, handshake: &Handshake) -> Result<(GroupState, AppKeyChain)>;
}

pub trait AddOperator: Sized {
    fn create_add_handshake(
        &self,
        new_roster_index: u32,
        public_key: DhPubKey,
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
    my_roster_index: u32,
    tree: RatchetTree,
    /// The initial secret used to derive app_secret.
    /// It works as a salt of HKDF.
    init_secret: HmacKey,
}

impl HandshakeProcessor for GroupState {
    fn process_handshake(&self, handshake: &Handshake) -> Result<(GroupState, AppKeyChain)> {
        ensure!(handshake.prior_epoch == self.epoch, "Handshake's prior epoch isn't the current epoch.");

        let sender_tree_idx = RatchetTree::roster_idx_to_tree_idx(handshake.roster_index())?;
        ensure!(sender_tree_idx < self.tree.size(), "Handshake's roster index is out of range.");

        let mut new_group_state = self.clone();
        new_group_state.increment_epoch()?;

        let new_group_epoch_secret = match handshake.op {
            GroupOperation::Add(ref add) => new_group_state.apply_add_op(add)?
        };



        unimplemented!();
    }
}

impl AddOperator for GroupState {
    fn create_add_handshake(
        &self,
        new_roster_index: u32,
        public_key: DhPubKey,
    ) -> Result<(Handshake, GroupState, AppKeyChain)> {
        let (new_group_state, app_key_chain, add_op) =
            self.update_by_add_op(new_roster_index, public_key)?;
        let prior_epoch = self.epoch;
        let handshake = Handshake::new(prior_epoch, add_op);

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
    pub fn new(private_key: DhPrivateKey) -> Self {
        let my_roster_index = 0;
        let epoch = 0;
        let init_secret = HmacKey::zero(SHA256_OUTPUT_LEN);
        let my_node = RatchetTreeNode::from_private_key(private_key);
        let tree = RatchetTree::new(vec![my_node]);

        GroupState {
            epoch,
            my_roster_index,
            tree,
            init_secret,
        }
    }

    fn update_by_add_op(
        &self,
        new_roster_index: u32,
        public_key: DhPubKey,
    ) -> Result<(GroupState, AppKeyChain, GroupOperation)> {
        let mut new_group_state = self.clone();
        let add_op = GroupAdd::new(new_roster_index, public_key);
        let update_secret = new_group_state.apply_add_op(&add_op)?;

        new_group_state.increment_epoch()?;
        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        Ok((new_group_state, app_key_chain, GroupOperation::Add(add_op)))
    }

    /// Add a new member to group state.
    fn apply_add_op(&mut self, add: &GroupAdd) -> Result<UpdateSecret> {
        let add_roster_index = add.roster_index;
        if add_roster_index as usize > self.tree.size() {
            return Err(anyhow!("Invalid roster index in add operation."));
        }

        let tree_index = RatchetTree::roster_idx_to_tree_idx(add_roster_index)?;
        self.tree.add_leaf_node(RatchetTreeNode::Blank);

        Ok(UpdateSecret::zero(SHA256_OUTPUT_LEN))
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

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn my_roster_index(&self) -> u32 {
        self.my_roster_index
    }

    pub fn roster_len(&self) -> Result<usize> {
        let tree_size = self.tree.size();
        tree_size
            .checked_div(2)
            .ok_or(anyhow!("Invalid tree size."))
    }
}
