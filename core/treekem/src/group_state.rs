use crate::crypto::{
    CryptoRng, SHA256_OUTPUT_LEN,
    hkdf,
    dh::{DhPrivateKey, DhPubKey},
    secrets::{GroupEpochSecret, AppSecret, UpdateSecret, PathSecret},
    hmac::HmacKey,
};
use crate::application::AppKeyChain;
use crate::handshake::HandshakeParams;
use crate::ratchet_tree::{RatchetTree, RatchetTreeNode};
use anyhow::{Result, anyhow, ensure};
use codec::Encode;


pub trait Handshake: Sized {
    fn create_handshake(
        &self,
        new_path_secret: PathSecret,
    ) -> Result<(HandshakeParams, GroupState, AppKeyChain)>;

    fn process_handshake(&self, handshake: &HandshakeParams) -> Result<(GroupState, AppKeyChain)>;
}

#[derive(Clone, Debug, Encode)]
pub struct GroupState {
    /// The current version of the group key
    epoch: u32,
    /// Only if a member has a leaf node contained DhPrivKey, this indicates the roster index.
    /// Otherwise, this field is None.
    my_roster_index: Option<u32>,
    tree: RatchetTree,
    /// The initial secret used to derive app_secret.
    /// It works as a salt of HKDF.
    init_secret: HmacKey,
}

impl Handshake for GroupState {
    fn create_handshake(
        &self,
        new_path_secret: PathSecret,
    ) -> Result<(HandshakeParams, GroupState, AppKeyChain)> {
        let mut new_group_state = self.clone();

        let my_roster_idx = match new_group_state.my_roster_index() {
            // update operation
            Some(idx) => idx as u32,
            // add operation
            None => {
                let current_roster_len = self.roster_len()? as u32;
                new_group_state.my_roster_index = Some(current_roster_len);
                current_roster_len
            }
        };
        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(my_roster_idx)?;

        let update_secret = new_group_state.set_new_path_secret(new_path_secret.clone(), my_tree_idx)?;
        new_group_state.increment_epoch()?;

        let direct_path_msg = new_group_state.tree.encrypt_direct_path_secret(my_tree_idx, new_path_secret.clone())?;

        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        // TODO: get pubkey from `set_new_path_secret` or `encrypt_direct_path_secret`
        let (pubkey,_,_,_) = new_path_secret.derive_node_values()?;

        let handshake = HandshakeParams {
            prior_epoch: self.epoch,
            roster_index: my_roster_idx,
            public_key: pubkey,
            path: direct_path_msg,
        };

        Ok((handshake, new_group_state, app_key_chain))
    }

    fn process_handshake(&self, handshake: &HandshakeParams) -> Result<(GroupState, AppKeyChain)> {
        ensure!(handshake.prior_epoch == self.epoch, "Handshake's prior epoch isn't the current epoch.");

        let mut new_group_state = self.clone();
        new_group_state.increment_epoch()?;

        let update_secret = new_group_state.apply_handshake(handshake)?;

        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        Ok((new_group_state, app_key_chain))
    }
}

impl GroupState {
    fn apply_handshake(&mut self, handshake: &HandshakeParams) -> Result<UpdateSecret> {
        let sender_tree_idx = RatchetTree::roster_idx_to_tree_idx(handshake.roster_index)?;
        let next_roster_idx = self.roster_len()?;

        let mut res = UpdateSecret::default();
        // If handshake's roster index is equal to the incremented index of max current roster index,
        // apply the handshake as an add operation.
        if sender_tree_idx == next_roster_idx {
            self.tree.add_leaf_node(RatchetTreeNode::Blank);
            self.tree.propagate_blank(sender_tree_idx);
            res = self.apply_operation(&handshake, sender_tree_idx)?;

        // If handshake's roster index is within the bounds of current roster index,
        // apply the handshake as an update operation.
        } else if sender_tree_idx < next_roster_idx {
            res = self.apply_operation(&handshake, sender_tree_idx)?;
        } else {
            return Err(anyhow!("Handshake's roster index is out of bounds."));
        }

        Ok(res)
    }

    fn apply_operation(
        &mut self,
        handshake: &HandshakeParams,
        sender_tree_idx: usize,
    ) -> Result<UpdateSecret> {
        // TODO: Currently, each member must not send handshake before setting path secrets.
        let my_roster_idx = self.my_roster_index()
            .ok_or(anyhow!("my_roster index must exist when receiving a handshake"))?;

        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(my_roster_idx)?;
        let (path_secret, common_ancestor) = self.tree.decrypt_direct_path_msg(
            &handshake.path,
            sender_tree_idx,
            my_tree_idx,
        )?;
        let update_secret = self.set_new_path_secret(path_secret, common_ancestor)?;

        let direct_path_pub_keys = handshake.path.node_msgs.iter().map(|m| &m.public_key);
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

    /// Request own new path secret to external key vault
    pub fn request_new_path_secret(&self, roster_idx: u32, epoch: u32) -> Result<PathSecret> {
        unimplemented!();
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn my_roster_index(&self) -> Option<u32> {
        self.my_roster_index
    }

    pub fn roster_len(&self) -> Result<usize> {
        let tree_size = self.tree.size();
        tree_size
            .checked_div(2)
            .ok_or(anyhow!("Invalid tree size."))
    }
}
