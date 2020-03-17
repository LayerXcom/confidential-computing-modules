use crate::crypto::{
    CryptoRng, SHA256_OUTPUT_LEN,
    hkdf,
    dh::{DhPrivateKey, DhPubKey},
    secrets::{GroupEpochSecret, AppSecret, UpdateSecret, PathSecret},
    hmac::HmacKey,
};
use crate::application::AppKeyChain;
use crate::handshake::{GroupAdd, GroupUpdate, GroupOperation, Handshake};
use crate::ratchet_tree::{RatchetTree, RatchetTreeNode};
use anyhow::{Result, anyhow, ensure};
use codec::Encode;

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
    fn create_update_handshake(
        &self,
        new_path_secret: PathSecret,
    ) -> Result<(Handshake, GroupState, AppKeyChain)>;
}

#[derive(Clone, Debug, Encode)]
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

        let update_secret = match handshake.op {
            GroupOperation::Add(ref add) => new_group_state.apply_add_op(add)?,
            GroupOperation::Update(ref update) => new_group_state.apply_update_op(update, sender_tree_idx)?,
        };

        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        Ok((new_group_state, app_key_chain))
    }
}

impl AddOperator for GroupState {
    fn create_add_handshake(
        &self,
        new_roster_index: u32,
        public_key: DhPubKey,
    ) -> Result<(Handshake, GroupState, AppKeyChain)> {
        let (new_group_state, app_key_chain, add_op) = self.apply_pubkey(new_roster_index, public_key)?;
        let handshake = Handshake::new(self.epoch, add_op);

        Ok((handshake, new_group_state, app_key_chain))
    }
}

impl UpdateOperator for GroupState {
    fn create_update_handshake(
        &self,
        new_path_secret: PathSecret,
    ) -> Result<(Handshake, GroupState, AppKeyChain)> {
        let mut new_group_state = self.clone();

        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(new_group_state.my_roster_index())?;
        let update_secret = new_group_state.set_new_path_secret(new_path_secret.clone(), my_tree_idx)?;
        new_group_state.increment_epoch()?;

        let direct_path_msg = new_group_state.tree.encrypt_direct_path_secret(my_tree_idx, new_path_secret)?;
        let op = GroupOperation::Update(GroupUpdate::new(direct_path_msg));
        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        let handshake = Handshake::new(self.epoch, op);

        Ok((handshake, new_group_state, app_key_chain))
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

    fn apply_pubkey(
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

    fn apply_update_op(
        &mut self,
        update: &GroupUpdate,
        sender_tree_idx: usize,
    ) -> Result<UpdateSecret> {
        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(self.my_roster_index())?;
        let (path_secret, common_ancestor) = self.tree.decrypt_direct_path_msg(
            &update.path,
            sender_tree_idx,
            my_tree_idx,
        )?;
        let update_secret = self.set_new_path_secret(path_secret, common_ancestor)?;

        let direct_path_pub_keys = update.path.node_msgs.iter().map(|m| &m.public_key);
        self.tree.set_public_keys(sender_tree_idx, common_ancestor, direct_path_pub_keys.clone())?;

        Ok(update_secret)
    }

    /// Set new path secret to group state.
    /// This updates direct path node's keypair and return updatesecret.
    fn set_new_path_secret(
        &mut self,
        new_path_secret: PathSecret,
        leaf_idx: usize
    ) -> Result<UpdateSecret> {
        self
            .tree
            .propagate_new_path_secret(new_path_secret, leaf_idx)
            .map(Into::into)
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
        let epoch_secret = hkdf::extract(&self.init_secret, update_secret.as_bytes());
        self.init_secret = hkdf::derive_secret(&epoch_secret, b"init", self)?;
        let app_secret = hkdf::derive_secret(&epoch_secret, b"app", self)?;

        Ok(app_secret.into())
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
