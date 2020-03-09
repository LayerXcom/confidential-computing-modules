use std::vec::Vec;
use crate::crypto::{DhPrivateKey, DhPubKey, HmacKey};
use crate::tree_math;
use anyhow::{Result, anyhow};

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

    pub fn encrypt_direct_path_secret() {

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
}

#[derive(Debug, Clone)]
pub struct PathSecret(HmacKey);

impl From<PathSecret> for HmacKey {
    fn from(path: PathSecret) -> Self {
        path.0
    }
}
