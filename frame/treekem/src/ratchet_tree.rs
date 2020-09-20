use crate::crypto::{
    dh::{DhPrivateKey, DhPubKey},
    ecies::EciesCiphertext,
    secrets::{NodeSecret, PathSecret},
};
use crate::{
    handshake::{DirectPathMsg, DirectPathNodeMsg},
    tree_math,
};
use anyhow::{anyhow, ensure, Result};
use codec::Encode;
use std::vec::Vec;

#[derive(Clone, Debug, Encode)]
pub struct RatchetTree {
    pub nodes: Vec<RatchetTreeNode>,
}

impl RatchetTree {
    pub fn new(nodes: Vec<RatchetTreeNode>) -> Self {
        RatchetTree { nodes }
    }

    pub fn new_empty() -> Self {
        RatchetTree { nodes: vec![] }
    }

    /// Set my leaf node derived from path secret to the provided tree index.
    pub fn init_path_secret_idx(path_secret: PathSecret, my_tree_idx: usize) -> Result<Self> {
        let (_, privkey, _, _) = path_secret.derive_node_values()?;
        let my_leaf = RatchetTreeNode::from_private_key(privkey);
        let mut nodes = vec![RatchetTreeNode::Blank; my_tree_idx];
        nodes.push(my_leaf);

        Ok(RatchetTree::new(nodes))
    }

    /// Construct a Direct Path Message containing encrypted ratcheted path secrets.
    pub fn encrypt_direct_path_secret(
        &self,
        leaf_idx: usize,
        path_secret: PathSecret,
    ) -> Result<DirectPathMsg> {
        ensure!(leaf_idx % 2 == 0, "index must be leaf's one.");
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_direct_path(leaf_idx, num_leaves);

        let mut node_msgs = vec![];
        let (leaf_public_key, _, _, mut parent_path_secret) = path_secret.derive_node_values()?;
        node_msgs.push(DirectPathNodeMsg::new(leaf_public_key, vec![]));
        if num_leaves == 1 {
            return Ok(DirectPathMsg::new(node_msgs));
        }

        for path_node_idx in direct_path {
            let (parent_public_key, _, _, grandparent_path_secret) =
                parent_path_secret.clone().derive_node_values()?;

            let mut encrypted_path_secrets = vec![];
            let copath_node_idx = tree_math::node_sibling(path_node_idx, num_leaves);
            for res_node in self
                .resolution(copath_node_idx)
                .iter()
                .map(|&i| &self.nodes[i])
            {
                let others_pub_key = res_node
                    .public_key()
                    .ok_or_else(|| anyhow!("The resoluted node doesn't contain public key"))?;

                let ciphertext = EciesCiphertext::encrypt(
                    &others_pub_key,
                    parent_path_secret.as_bytes().to_vec(), // TODO:
                )?;
                encrypted_path_secrets.push(ciphertext);
            }

            node_msgs.push(DirectPathNodeMsg::new(
                parent_public_key.clone(),
                encrypted_path_secrets,
            ));
            parent_path_secret = grandparent_path_secret;
        }

        Ok(DirectPathMsg::new(node_msgs))
    }

    pub fn decrypt_direct_path_msg(
        &self,
        direct_path_msg: &DirectPathMsg,
        others_leaf_idx: usize,
        my_leaf_idx: usize,
    ) -> Result<(PathSecret, usize)> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        ensure!(
            others_leaf_idx <= self.size() && my_leaf_idx <= self.size(),
            "Leaf indices are out of range"
        );
        ensure!(
            !tree_math::is_ancestor(others_leaf_idx, my_leaf_idx, num_leaves)
                && !tree_math::is_ancestor(my_leaf_idx, others_leaf_idx, num_leaves),
            "Cannot decrypt messages from ancestors or descendants"
        );

        // An index of the intermediate node in the common direct path.
        let common_ancestor_idx =
            tree_math::common_ancestor(others_leaf_idx, my_leaf_idx, num_leaves);
        // A node message for me is a common ancestor.
        let node_msg = {
            let (pos_msg, _) = tree_math::node_extended_direct_path(others_leaf_idx, num_leaves)
                .enumerate()
                .find(|&(_, dp_idx)| dp_idx == common_ancestor_idx)
                .ok_or_else(|| anyhow!("Common ancestor cannot be found in the direct path."))?;
            direct_path_msg
                .node_msgs
                .get(pos_msg)
                .ok_or_else(|| anyhow!("Invalid direct path message"))?
        };

        // Receiver's copath of the common ancestor node
        let copath_common_ancestor_idx = {
            let left = tree_math::node_left_child(common_ancestor_idx);
            let right = tree_math::node_right_child(common_ancestor_idx, num_leaves);
            if tree_math::is_ancestor(left, my_leaf_idx, num_leaves) {
                left
            } else {
                right
            }
        };

        // Find the resolution of copath_common_ancestor_idx
        let resolution = self.resolution(copath_common_ancestor_idx);
        for (pos, idx) in resolution.into_iter().enumerate() {
            let res_node = self
                .get(idx)
                .ok_or_else(|| anyhow!("resolution index is out of range"))?;
            if res_node.private_key().is_some()
                && tree_math::is_ancestor(idx, my_leaf_idx, num_leaves)
            {
                let decryption_key = res_node.private_key().unwrap();
                let plaintext = node_msg
                    .node_secrets
                    .get(pos)
                    .ok_or_else(|| anyhow!("Invalid direct path message"))?
                    .clone()
                    .decrypt(&decryption_key)?;
                let path_secret = PathSecret::from(plaintext);

                return Ok((path_secret, common_ancestor_idx));
            }
        }

        Err(anyhow!("Cannot find node in the resolution."))
    }

    pub fn add_leaf_node(&mut self, node: RatchetTreeNode) {
        if self.nodes.is_empty() {
            self.nodes.push(node);
        } else {
            self.nodes.push(RatchetTreeNode::Blank);
            self.nodes.push(node);
        }
    }

    pub fn propagate_blank(&mut self, leaf_idx: usize) {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_extended_direct_path(leaf_idx, num_leaves);
        for i in direct_path {
            self.nodes[i] = RatchetTreeNode::Blank;
        }
    }

    /// Propagate new path secret from leaf node to root node.
    pub fn propagate_new_path_secret(
        &mut self,
        mut path_secret: PathSecret,
        leaf_idx: usize,
    ) -> Result<NodeSecret> {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let root_node_idx = tree_math::root_idx(num_leaves);
        let mut current_node_idx = leaf_idx;

        let root_node_secret = loop {
            let current_node = self.get_mut(current_node_idx).expect("Invalid node index.");
            let (node_pubkey, node_privkey, node_secret, parent_path_secret) =
                path_secret.derive_node_values()?;

            current_node.update_pub_key(node_pubkey);
            current_node.update_priv_key(node_privkey);

            if current_node_idx == root_node_idx {
                break node_secret;
            } else {
                current_node_idx = tree_math::node_parent(current_node_idx, num_leaves);
                path_secret = parent_path_secret;
            }
        };

        if num_leaves == 1 {
            return Ok(NodeSecret::default());
        }

        Ok(root_node_secret)
    }

    pub fn set_single_public_key(&mut self, tree_idx: usize, pubkey: DhPubKey) -> Result<()> {
        let node = self.get_mut(tree_idx).ok_or_else(|| {
            anyhow!("Invalid tree index. Cannot set a public key to ratchet tree by add operation")
        })?;
        node.update_pub_key(pubkey);

        Ok(())
    }

    /// Set the public keys.
    pub fn set_public_keys<'a, I>(
        &mut self,
        start_idx: usize,
        stop_idx: usize,
        mut public_keys: I,
    ) -> Result<()>
    where
        I: Iterator<Item = &'a DhPubKey>,
    {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        // direct path including a root
        let direct_path = tree_math::node_extended_direct_path(start_idx, num_leaves);
        for path_node_idx in direct_path {
            let pubkey = match public_keys.next() {
                Some(p) => p,
                None => break,
            };

            if path_node_idx == stop_idx {
                break;
            } else {
                let node = self
                    .get_mut(path_node_idx)
                    .ok_or_else(|| anyhow!("Direct path node is out of range"))?;
                node.update_pub_key(pubkey.clone());
            }
        }

        Ok(())
    }

    /// Convert a roster index into a ratchet tree index.
    /// tree index is just two times of roster index.
    pub fn roster_idx_to_tree_idx(roster_idx: u32) -> Result<usize> {
        roster_idx
            .checked_mul(2)
            .map(|i| i as usize)
            .ok_or_else(|| anyhow!("Invalid roster or tree index."))
    }

    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    pub fn get(&self, idx: usize) -> Option<&RatchetTreeNode> {
        self.nodes.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut RatchetTreeNode> {
        self.nodes.get_mut(idx)
    }

    /// See: section 5.2
    /// Return an ordered list of non-blank nodes that collectively cover all non-blank descendants
    /// of the node.
    /// The ordering is ascending by node index.
    fn resolution(&self, idx: usize) -> Vec<usize> {
        fn helper(tree: &RatchetTree, idx: usize, acc: &mut Vec<usize>) {
            if let RatchetTreeNode::Blank = tree.nodes[idx] {
                match tree_math::node_level(idx) {
                    0 => return,
                    _ => {
                        let num_leaves = tree_math::num_leaves_in_tree(tree.size());
                        helper(tree, tree_math::node_left_child(idx), acc);
                        helper(tree, tree_math::node_right_child(idx, num_leaves), acc);
                    }
                }
            } else {
                acc.push(idx);
            }
        }

        let mut acc = vec![];
        helper(self, idx, &mut acc);
        acc
    }
}

/// A node in RatchetTree. Every node must have a DH public key.
/// It may also optionally contain the corresponding private key.
#[derive(Debug, Clone, Encode)]
pub enum RatchetTreeNode {
    Blank,
    Filled {
        public_key: DhPubKey,
        #[codec(skip)]
        private_key: Option<DhPrivateKey>,
    },
}

impl RatchetTreeNode {
    pub fn from_private_key(private_key: DhPrivateKey) -> Self {
        let public_key = DhPubKey::from_private_key(&private_key);
        RatchetTreeNode::Filled {
            public_key,
            private_key: Some(private_key),
        }
    }

    pub fn update_priv_key(&mut self, new_priv_key: DhPrivateKey) {
        match self {
            RatchetTreeNode::Blank => panic!("tried to update private key of blank node"),
            RatchetTreeNode::Filled {
                ref mut private_key,
                ..
            } => {
                *private_key = Some(new_priv_key);
            }
        }
    }

    pub fn update_pub_key(&mut self, new_pub_key: DhPubKey) {
        match self {
            RatchetTreeNode::Blank => {
                *self = RatchetTreeNode::Filled {
                    public_key: new_pub_key,
                    private_key: None,
                };
            }
            RatchetTreeNode::Filled {
                ref mut public_key, ..
            } => *public_key = new_pub_key,
        }
    }

    pub fn private_key(&self) -> Option<&DhPrivateKey> {
        match self {
            RatchetTreeNode::Blank => None,
            RatchetTreeNode::Filled {
                ref private_key, ..
            } => private_key.as_ref(),
        }
    }

    pub fn public_key(&self) -> Option<&DhPubKey> {
        match self {
            RatchetTreeNode::Blank => None,
            RatchetTreeNode::Filled { ref public_key, .. } => Some(public_key),
        }
    }
}
