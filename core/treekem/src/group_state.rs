use crate::crypto::{
    CryptoRng, SHA256_OUTPUT_LEN,
    hkdf,
    dh::{DhPrivateKey, DhPubKey},
    secrets::*,
    hmac::HmacKey,
};
use crate::application::AppKeyChain;
use crate::handshake::{HandshakeParams};
use crate::ratchet_tree::{RatchetTree, RatchetTreeNode};
use crate::tree_math;
use anyhow::{Result, anyhow, ensure};
use codec::Encode;

pub trait Handshake: Sized {
    fn create_handshake(&self, req: &PathSecretRequest) -> Result<HandshakeParams>;

    fn process_handshake(&mut self, handshake: &HandshakeParams, req: &PathSecretRequest) -> Result<AppKeyChain>;
}

#[derive(Clone, Debug, Encode)]
pub struct GroupState {
    /// The current version of the group key
    epoch: u32,
    /// Only if a member has a leaf node contained DhPrivKey, this indicates the roster index.
    /// Otherwise, this field is None.
    #[codec(skip)]
    pub my_roster_idx: u32,
    tree: RatchetTree,
    /// The initial secret used to derive app_secret.
    /// It works as a salt of HKDF.
    #[codec(skip)]
    init_secret: HmacKey,
}

impl Handshake for GroupState {
    fn create_handshake(&self, req: &PathSecretRequest) -> Result<HandshakeParams> {
        let my_roster_idx = self.my_roster_idx;
        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(my_roster_idx)?;

        let path_secret = Self::request_new_path_secret(req, my_roster_idx, self.epoch)?;
        let mut new_group_state = self.clone();

        if my_tree_idx == self.tree.size() {
            new_group_state.tree.add_leaf_node(RatchetTreeNode::Blank);
            new_group_state.tree.propagate_blank(my_roster_idx as usize);
        }

        let update_secret = new_group_state.set_new_path_secret(path_secret.clone(), my_tree_idx)?;
        new_group_state.increment_epoch()?;
        let direct_path_msg = new_group_state.tree.encrypt_direct_path_secret(my_tree_idx, path_secret.clone())?;

        let handshake = HandshakeParams {
            prior_epoch: self.epoch,
            roster_idx: my_roster_idx,
            path: direct_path_msg
        };

        Ok(handshake)
    }

    fn process_handshake(&mut self, handshake: &HandshakeParams, req: &PathSecretRequest) -> Result<AppKeyChain> {
        ensure!(handshake.prior_epoch == self.epoch, "Handshake's prior epoch isn't the current epoch.");
        let sender_tree_idx = RatchetTree::roster_idx_to_tree_idx(handshake.roster_idx)?;
        ensure!(sender_tree_idx <= self.tree.size(), "Invalid tree index");

        if sender_tree_idx == self.tree.size() {
            if self.tree.nodes.is_empty() {
                self.tree.add_leaf_node(RatchetTreeNode::Blank);
            }
            self.tree.add_leaf_node(RatchetTreeNode::Blank);
            self.tree.propagate_blank(sender_tree_idx);
        }

        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(self.my_roster_idx)?;
        let mut my_path_secret: Option<PathSecret> = None;
        if let Some(my_leaf) = self.tree.get_mut(my_tree_idx) {
            if sender_tree_idx == my_tree_idx {
                let path_secret = Self::request_new_path_secret(req, self.my_roster_idx, self.epoch)?;
                let (node_pubkey, node_privkey, _, _) = path_secret.clone().derive_node_values()?;

                my_leaf.update_pub_key(node_pubkey);
                my_leaf.update_priv_key(node_privkey);

                my_path_secret = Some(path_secret);
            }
        }

        let (update_secret, common_ancestor) = self.apply_handshake(handshake, sender_tree_idx, my_path_secret)?;
        let direct_path_pub_keys = handshake.path.node_msgs.iter().map(|m| &m.public_key);
        self.tree.set_public_keys(sender_tree_idx, common_ancestor, direct_path_pub_keys.clone())?;
        self.increment_epoch()?;

        let app_secret = self.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&self, app_secret);

        Ok(app_key_chain)
    }
}

impl GroupState {
    pub fn new(my_roster_idx: u32) -> Result<Self> {
        let epoch = 0;
        let tree = RatchetTree::new_empty();
        let init_secret = HmacKey::default();

        Ok(GroupState {
            epoch,
            my_roster_idx,
            tree,
            init_secret,
        })
    }

    fn apply_handshake(&mut self, handshake: &HandshakeParams, sender_tree_idx: usize, path_secret: Option<PathSecret>) -> Result<(UpdateSecret, usize)> {
        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(self.my_roster_idx)?;

        match self.tree.get(0).unwrap() {
            &RatchetTreeNode::Blank => {
                let num_leaves = tree_math::num_leaves_in_tree(self.tree.size());
                let common_ancestor = tree_math::common_ancestor(sender_tree_idx, my_tree_idx, num_leaves);
                Ok((UpdateSecret::default(), common_ancestor))
            }
            _ => {
                match sender_tree_idx == my_tree_idx {
                    true => {
                        let update_secret = self.set_new_path_secret(path_secret.unwrap(), my_tree_idx)?;
                        return Ok((update_secret, my_tree_idx))
                    },
                    false => {
                        let (path_secret, common_ancestor) = self.tree.decrypt_direct_path_msg(
                            &handshake.path,
                            sender_tree_idx,
                            my_tree_idx,
                        )?;
                        let update_secret = self.set_new_path_secret(path_secret, common_ancestor)?;
                        Ok((update_secret, common_ancestor))
                    }
                }
            }
        }
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
        // let epoch_secret = hkdf::extract(&self.init_secret, update_secret.as_bytes());
        self.init_secret = hkdf::derive_secret(&update_secret.into(), b"init", self)?;
        let app_secret = hkdf::derive_secret(&update_secret.into(), b"app", self)?;

        Ok(app_secret.into())
    }

    /// Request own new path secret to external key vault
    pub fn request_new_path_secret(req: &PathSecretRequest, roster_idx: u32, epoch: u32) -> Result<PathSecret> {
        match req {
            PathSecretRequest::Local(db) => {
                db.get(roster_idx, epoch).cloned().ok_or(anyhow!("Not found Path Secret from local PathSecretKVS with provided roster_idx and epoch"))
            },
            PathSecretRequest::Remote(url) => unimplemented!(),
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn my_roster_idx(&self) -> u32 {
        self.my_roster_idx
    }

    pub fn roster_len(&self) -> Result<usize> {
        let tree_size = self.tree.size();
        tree_size
            .checked_div(2)
            .ok_or(anyhow!("Invalid tree size."))
    }
}
