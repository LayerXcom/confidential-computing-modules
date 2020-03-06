use std::vec::Vec;
use crate::crypto::{DhPrivateKey, DhPubKey};

#[derive(Clone, Debug)]
pub struct RatchetTree {
    nodes: Vec<RachetTreeNode>,
}

impl RatchetTree {
    pub fn size(&self) -> usize {
        self.nodes.len()
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
