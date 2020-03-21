use crate::crypto::{
    CryptoRng, SHA256_OUTPUT_LEN,
    hkdf,
    dh::{DhPrivateKey, DhPubKey},
    secrets::*,
    hmac::HmacKey,
};
use crate::application::AppKeyChain;
use crate::handshake::{HandshakeParams, GroupOperation, GroupAdd, GroupUpdate};
use crate::ratchet_tree::{RatchetTree, RatchetTreeNode};
use anyhow::{Result, anyhow, ensure};
use codec::Encode;

pub trait Handshake: Sized {
    fn create_add_handshake(&self, req: &PathSecretRequest) -> Result<HandshakeParams>;

    fn create_update_handshake(&self, req: &PathSecretRequest) -> Result<(HandshakeParams, GroupState, AppKeyChain)>;

    fn process_handshake(&self, handshake: &HandshakeParams) -> Result<(GroupState, Option<AppKeyChain>)>;
}

#[derive(Clone, Debug, Encode)]
pub struct GroupState {
    /// The current version of the group key
    epoch: u32,
    /// Only if a member has a leaf node contained DhPrivKey, this indicates the roster index.
    /// Otherwise, this field is None.
    pub my_roster_idx: u32,
    tree: RatchetTree,
    /// The initial secret used to derive app_secret.
    /// It works as a salt of HKDF.
    init_secret: HmacKey,
}

impl Handshake for GroupState {
    fn create_add_handshake(&self, req: &PathSecretRequest) -> Result<HandshakeParams> {
        let roster_idx = self.my_roster_idx;
        let path_secret = Self::request_new_path_secret(req, roster_idx, self.epoch)?;

        let (pubkey,_,_,_) = path_secret.derive_node_values()?;
        let add_op = GroupAdd::new(pubkey);

        let handshake = HandshakeParams {
            prior_epoch: self.epoch,
            roster_idx,
            op: GroupOperation::Add(add_op),
        };

        Ok(handshake)
    }

    fn create_update_handshake(&self, req: &PathSecretRequest) -> Result<(HandshakeParams, GroupState, AppKeyChain)> {
        let roster_idx = self.my_roster_idx;
        let mut new_group_state = self.clone();

        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(roster_idx)?;
        let path_secret = Self::request_new_path_secret(req, roster_idx, self.epoch)?;

        let update_secret = new_group_state.set_new_path_secret(path_secret.clone(), my_tree_idx)?;
        new_group_state.increment_epoch()?;

        let direct_path_msg = new_group_state.tree.encrypt_direct_path_secret(my_tree_idx, path_secret.clone())?;

        let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
        let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

        let update_op = GroupUpdate::new(direct_path_msg);

        let handshake = HandshakeParams {
            prior_epoch: self.epoch,
            roster_idx,
            op: GroupOperation::Update(update_op),
        };

        Ok((handshake, new_group_state, app_key_chain))
    }

    fn process_handshake(&self, handshake: &HandshakeParams) -> Result<(GroupState, Option<AppKeyChain>)> {
        ensure!(handshake.prior_epoch == self.epoch, "Handshake's prior epoch isn't the current epoch.");
        let sender_tree_idx = RatchetTree::roster_idx_to_tree_idx(handshake.roster_idx)?;

        let mut new_group_state = self.clone();

        match handshake.op {
            GroupOperation::Add(ref add) => {
                new_group_state.apply_add_operation(add.clone(), handshake.roster_idx)?;

                Ok((new_group_state, None))
            },
            GroupOperation::Update(ref update) => {
                let update_secret = new_group_state.apply_update_operation(update, sender_tree_idx)?;
                new_group_state.increment_epoch()?;

                let app_secret = new_group_state.update_epoch_secret(&update_secret)?;
                let app_key_chain = AppKeyChain::from_app_secret(&new_group_state, app_secret);

                Ok((new_group_state, Some(app_key_chain)))
            },
        }
    }
}

impl GroupState {
    pub fn new(my_roster_idx: u32, req: &PathSecretRequest) -> Result<Self> {
        let epoch = 0;
        let path_secret = Self::request_new_path_secret(req, my_roster_idx, epoch)?;
        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(my_roster_idx)?;
        let tree = RatchetTree::init_path_secret_idx(path_secret, my_tree_idx)?;
        let init_secret = HmacKey::default();

        Ok(GroupState {
            epoch,
            my_roster_idx,
            tree,
            init_secret,
        })
    }

    fn apply_add_operation(&mut self, add_op: GroupAdd, roster_idx: u32) -> Result<()> {
        let sender_tree_idx = RatchetTree::roster_idx_to_tree_idx(roster_idx)?;
        self.tree.set_single_public_key(sender_tree_idx, add_op.public_key)?;

        Ok(())
    }

    fn apply_update_operation(&mut self, update_opp: &GroupUpdate, sender_tree_idx: usize) -> Result<UpdateSecret> {
        ensure!(sender_tree_idx < self.tree.size(), "Handshake's roster index is out of bounds");

        let my_tree_idx = RatchetTree::roster_idx_to_tree_idx(self.my_roster_idx)?;
        let (path_secret, common_ancestor) = self.tree.decrypt_direct_path_msg(
            &update_opp.path,
            sender_tree_idx,
            my_tree_idx,
        )?;
        let update_secret = self.set_new_path_secret(path_secret, common_ancestor)?;

        let direct_path_pub_keys = update_opp.path.node_msgs.iter().map(|m| &m.public_key);
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
