use std::vec::Vec;
use crate::crypto::{DhPrivateKey, DhPubKey};
use crate::tree_math;
use anyhow::{Result, anyhow};

#[derive(Clone, Debug)]
pub struct RatchetTree {
    nodes: Vec<RachetTreeNode>,
}

impl RatchetTree {
    pub fn size(&self) -> usize {
        self.nodes.len()
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
}

/// A node in RatchetTree. Every node must have a DH public key.
/// It may also optionally contain the corresponding private key.
#[derive(Debug, Clone)]
pub enum RachetTreeNode {
    Blank,
    Filled {
        pub_key: DhPubKey,
        private_key: Option<DhPrivateKey>,
    },
}

impl RachetTreeNode {
    pub fn from_private_key(private_key: DhPrivateKey) -> Self {
        let pub_key = DhPubKey::from_private_key(&private_key);
        RachetTreeNode::Filled {
            pub_key,
            private_key: Some(private_key),
        }
    }
}
