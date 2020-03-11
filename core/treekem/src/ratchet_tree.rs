use std::vec::Vec;
use crate::crypto::{
    dh::{DhPrivateKey, DhPubKey},
    secrets::{HmacKey, PathSecret},
    ecies::EciesCiphertext,
    CryptoRng,
};
use crate::tree_math;
use anyhow::{Result, anyhow, ensure};

#[derive(Clone, Debug)]
pub struct RatchetTree {
    nodes: Vec<RachetTreeNode>,
}

impl RatchetTree {
    pub fn new(nodes: Vec<RachetTreeNode>) -> Self {
        RatchetTree { nodes }
    }

    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    pub fn get(&self, idx: usize) -> Option<&RachetTreeNode> {
        self.nodes.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut RachetTreeNode> {
        self.nodes.get_mut(idx)
    }

    pub fn add_leaf_node(&mut self, node: RachetTreeNode) {
        match self.nodes.is_empty() {
            true => self.nodes.push(node),
            false => {
                self.nodes.push(RachetTreeNode::Blank);
                self.nodes.push(node);
            },
        }
    }

    /// Convert a roster index into a ratchet tree index.
    /// tree index is just two times of roster index.
    pub fn roster_idx_to_tree_idx(roster_idx: u32) -> Result<usize> {
        roster_idx
            .checked_mul(2)
            .map(|i| i as usize)
            .ok_or(anyhow!("Invalid roster or tree index."))
    }

    pub fn create_blank_to_root(&mut self, start_idx: usize) {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_extended_direct_path(start_idx, num_leaves);
        for i in direct_path {
            self.nodes[i] = RachetTreeNode::Blank;
        }
    }

    /// Construct a Direct Path Message containing encrypted ratcheted path secrets.
    pub fn encrypt_direct_path_secret<R: CryptoRng>(
        &self,
        leaf_idx: usize,
        path_secret: PathSecret,
        csprng: &mut R,
    ) -> Result<DirectPathMsg> {
        ensure!(leaf_idx % 2 == 0, "index must be leaf's one.");
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        let direct_path = tree_math::node_direct_path(leaf_idx, num_leaves);

        let mut node_msgs = vec![];
        let (leaf_public_key, _, _, mut parent_path_secret) = path_secret.derive_node_values()?;
        node_msgs.push(DirectPathNodeMsg::new(leaf_public_key, vec![]));

        for path_node_idx in direct_path {
            let (parent_public_key, _, _, grandparent_path_secret) =
                parent_path_secret.clone().derive_node_values()?;

                let mut encrypted_path_secrets = vec![];
                let copath_node_idx = tree_math::node_sibling(path_node_idx, num_leaves);
                for res_node in self.resolution(copath_node_idx).iter().map(|&i| &self.nodes[i]) {
                    let others_pub_key = res_node
                        .public_key()
                        .ok_or(anyhow!("The resoluted node doesn't contain public key"))?;

                    let ciphertext = EciesCiphertext::encrypt(
                        &others_pub_key,
                        parent_path_secret.as_bytes().to_vec(), // TODO:
                    )?;
                    encrypted_path_secrets.push(ciphertext);
                }

                node_msgs.push(DirectPathNodeMsg::new(parent_public_key.clone(), encrypted_path_secrets));
                parent_path_secret = grandparent_path_secret;
        }

        Ok(DirectPathMsg::new(node_msgs))
    }

    /// See: section 5.2
    /// Return an ordered list of non-blank nodes that collectively cover all non-blank descendants
    /// of the node.
    /// The ordering is ascending by node index.
    pub fn resolution(&self, idx: usize) -> Vec<usize> {
        fn helper(tree: &RatchetTree, idx: usize, acc: &mut Vec<usize>) {
            if let RachetTreeNode::Blank = tree.nodes[idx] {
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

    /// Set the public keys.
    pub fn set_public_keys<'a, I>(
        &mut self,
        start_idx: usize,
        stop_idx: usize,
        mut public_keys: I,
    ) -> Result<()>
    where
        I: Iterator<Item = &'a DhPubKey>
    {
        let num_leaves = tree_math::num_leaves_in_tree(self.size());
        // direct path including a root
        let direct_path = tree_math::node_extended_direct_path(start_idx, num_leaves);
        for path_node_idx in direct_path {
            let pubkey = public_keys.next()
                .ok_or(anyhow!("length of direct path is longer than public key iterator"))?;
            if path_node_idx == stop_idx {
                break;
            } else {
                let node = self.get_mut(path_node_idx)
                    .ok_or(anyhow!("Direct path node is out of range"))?;
                node.update_pub_key(pubkey.clone());
            }
        }

        Ok(())
    }
}

/// A node in RatchetTree. Every node must have a DH public key.
/// It may also optionally contain the corresponding private key.
#[derive(Debug, Clone)]
pub enum RachetTreeNode {
    Blank,
    Filled {
        public_key: DhPubKey,
        private_key: Option<DhPrivateKey>,
    },
}

impl RachetTreeNode {
    pub fn from_private_key(private_key: DhPrivateKey) -> Self {
        let public_key = DhPubKey::from_private_key(&private_key);
        RachetTreeNode::Filled {
            public_key,
            private_key: Some(private_key),
        }
    }

    pub fn update_pub_key(&mut self, new_pub_key: DhPubKey) {
        match self {
            RachetTreeNode::Blank => {
                *self = RachetTreeNode::Filled {
                    public_key: new_pub_key,
                    private_key: None,
                };
            }
            RachetTreeNode::Filled {
                ref mut public_key,
                ..
            } => *public_key = new_pub_key,
        }
    }

    pub fn public_key(&self) -> Option<&DhPubKey> {
        match self {
            RachetTreeNode::Blank => None,
            RachetTreeNode::Filled {
                ref public_key,
                ..
            } => Some(public_key),
        }
    }
}

/// Encrypted
#[derive(Debug, Clone)]
pub struct DirectPathMsg {
    node_msgs: Vec<DirectPathNodeMsg>,
}

impl DirectPathMsg {
    pub fn new(node_msgs: Vec<DirectPathNodeMsg>) -> Self {
        DirectPathMsg { node_msgs }
    }
}

/// Containes a direc
#[derive(Debug, Clone)]
pub struct DirectPathNodeMsg {
    public_key: DhPubKey,
    node_secrets: Vec<EciesCiphertext>,
}

impl DirectPathNodeMsg {
    pub fn new(public_key: DhPubKey, node_secrets: Vec<EciesCiphertext>) -> Self {
        DirectPathNodeMsg { public_key, node_secrets }
    }
}
