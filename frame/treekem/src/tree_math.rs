//! This module defines all the tree operations we'll need to use when working with left-balanced
//! binary trees. For more info, see section 5.1 of the MLS spec.
//! referemnce: https://github.com/trailofbits/molasses/blob/master/src/tree_math.rs

use std::vec::Vec;

// Suppose usize is u64. If there are k := 2^(63)+1 leaves, then there are a total of 2(k-1) + 1 =
// 2(2^(63))+1 = 2^(64)+1 nodes in the tree, which is outside the representable range. So our upper
// bound is 2^(63) leaves, which gives a tree with 2^(64)-1 nodes.
pub(crate) const MAX_LEAVES: usize = (std::usize::MAX >> 1) + 1;

/// Returns `Some(floor(log2(x))` when `x != 0`, and `None` otherwise
fn log2(x: usize) -> Option<usize> {
    // The log2 of x is the position of its most significant bit
    let bitlen = (0usize).leading_zeros() as usize;
    (bitlen - x.leading_zeros() as usize).checked_sub(1)
}

/// Computes the level of a given node in a binary left-balanced tree. Leaves are level 0, their
/// parents are level 1, etc. If a node's children are at different level, then its level is the
/// max level of its children plus one.
pub(crate) fn node_level(idx: usize) -> usize {
    // The level of idx is equal to the number of trialing 1s in its binary representation.
    // Equivalently, this is just the number of trailing zeros of (NOT idx)
    (!idx).trailing_zeros() as usize
}

/// Computes the number of nodes needed to represent a tree with `num_leaves` many leaves
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
pub(crate) fn num_nodes_in_tree(num_leaves: usize) -> usize {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    2 * (num_leaves - 1) + 1
}

/// Computes the number of leaves in a tree of `num_nodes` many nodes
///
/// Panics: when `num_nodes` is odd, since all left-balanced binary trees have an odd number of
/// nodes
pub(crate) fn num_leaves_in_tree(num_nodes: usize) -> usize {
    assert!(num_nodes % 2 == 1);
    // Inverting the formula for num_nodes_in_tree, we get num_leaves = (num_nodes-1)/2 + 1
    ((num_nodes - 1) >> 1) + 1
}

/// Computes the index of the root node of a tree with `num_leaves` many leaves
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES`
pub(crate) fn root_idx(num_leaves: usize) -> usize {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    // Root nodes are always index 2^n - 1 where n is the smallest number such that the size of the
    // tree is less than the next power of 2, i.e., 2^(n+1).
    let n = num_nodes_in_tree(num_leaves);
    (1 << log2(n).unwrap()) - 1
}

/// Computes the index of the left child of a given node. This does not depend on the size of the
/// tree. The child of a leaf is itself.
pub(crate) fn node_left_child(idx: usize) -> usize {
    let lvl = node_level(idx);
    // The child of a leaf is itself
    if lvl == 0 {
        idx
    } else {
        // Being on the n-th level (index 0) means your index is of the form xyz..01111...1 where
        // x,y,z are arbitrary, and there are n-many ones at the end. Stepping to the left is
        // equivalent to clearing the highest trailing 1.
        idx ^ (0x01 << (lvl - 1))
    }
}

/// Computes the index of the left child of the given node. The child of a leaf is itself.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_right_child(idx: usize, num_leaves: usize) -> usize {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(idx < num_nodes_in_tree(num_leaves));

    let lvl = node_level(idx);
    // The child of a leaf is itself
    if lvl == 0 {
        idx
    } else {
        // Being on the n-th level (index 0) means your index is of the form xyz..01111...1 where
        // x,y,z are arbitrary, and there are n-many ones at the end. Stepping to the right is
        // equivalent to setting the rightmost 0 to a 1 and the highest trailing 1 to a 0. However,
        // this node might not exist (e.g., in a tree of 3 leaves, the right child of the root node
        // (idx 3) is the node with idx 4, not 5, since the rightmost tree isn't full). So we start
        // at the conjectured node and move left until we are within the bounds of the tree. This
        // is guaranteed to terminate, because if it didn't, there couldn't be any nodes with index
        // higher than the parent, which violates the invariant that every non-leaf node has two
        // children.
        let mut r = idx ^ (0x03 << (lvl - 1));
        let idx_threshold = num_nodes_in_tree(num_leaves);
        while r >= idx_threshold {
            r = node_left_child(r);
        }

        r
    }
}

/// Computes the index of the parent of a given node. The parent of the root is the root.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_parent(idx: usize, num_leaves: usize) -> usize {
    // The immediate parent of a node. May be beyond the right edge of the tree. This means weird
    // overflowing behavior when i == usize::MAX. However, this case is caught by the check below
    // that idx == root_idx(num_leaves). We hit the overflowing case iff idx is usize::MAX, which
    // is of the form 2^n - 1 for some n, which means that it's the root of a completely full tree
    // or it's the root of a subtree with more than `MAX_LEAVES` elements. The former case is
    // handled by the first if-statement below, and the latter is handled by the assert below.
    fn parent_step(i: usize) -> usize {
        // Recall that the children of xyz...0111...1 are xyz...0011...1 and xyz...1011...1 Working
        // backwards, this means that the parent of something that ends with 0011...1 or
        // 1011...1 is 0111...1. So if i is the index of the least significant 0, we must clear the
        // (i+1)-th bit and set the i-th bit.
        // This might be off the edge of the tree, since if, say, we have a tree on 3 leaves, the
        // rightmost leaf is idx 4, whose parent according to this algorithm would be idx 5, which
        // doesn't exist.
        let lvl = node_level(i);
        let bit_to_clear = i & (0x01 << (lvl + 1));
        let bit_to_set = 0x01 << lvl;

        (i | bit_to_set) ^ bit_to_clear
    }

    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(idx < num_nodes_in_tree(num_leaves));

    if idx == root_idx(num_leaves) {
        idx
    } else {
        // First assume we're in a full tree. This means we're assuming the direct path of this
        // node is maximally long.
        let mut p = parent_step(idx);
        let idx_threshold = num_nodes_in_tree(num_leaves);
        // This must terminate, since stepping up will eventually land us at the root node of the
        // tree, and parent_step increases the level at every step. The algorithm is correct, since
        // the direct path of the node of index i ocurring in a non-full subtree is a subpath of
        // the node of index i ocurring in a full subtree. Since they share an ancestor, we'll
        // eventually reach it if we start from the bottom and work our way up.
        while p >= idx_threshold {
            p = parent_step(p);
        }

        p
    }
}

/// Finds the minmal common ancestor of the given nodes. Here, minimal means having the smallest
/// node level. By convention, we say that the common ancestor of `a` and `a` is `a`.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or `idx1 >=
/// num_nodes_in_tree(num_leaves)` or `idx2 >= num_nodes_in_tree(num_leaves)`
pub(crate) fn common_ancestor(idx1: usize, idx2: usize, num_leaves: usize) -> usize {
    // We will compute the direct paths of both and find the first location where they begin to
    // agree. If they never agree, then their common ancestor is the root node

    // We have to allocate because our implementation of node_direct_path isn't reversible as-is
    let idx1_dp: Vec<usize> = node_direct_path(idx1, num_leaves).collect();
    let idx2_dp: Vec<usize> = node_direct_path(idx2, num_leaves).collect();

    // We iterate backwards through the direct paths and stop after we find the first place where
    // they disagree
    let mut common_ancestor = root_idx(num_leaves);
    for (&a, &b) in idx1_dp.iter().rev().zip(idx2_dp.iter().rev()) {
        if a == b {
            common_ancestor = a;
        } else {
            break;
        }
    }

    common_ancestor
}

/// Returns whether the node at index `a` is an ancestor of the node at index `b`. By convention,
/// we say that `a` is its own ancestor.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or `idx1 >=
/// num_nodes_in_tree(num_leaves)` or `idx2 >= num_nodes_in_tree(num_leaves)`
pub(crate) fn is_ancestor(a: usize, b: usize, num_leaves: usize) -> bool {
    let mut curr_idx = b;
    let root = root_idx(num_leaves);

    // Try to find a along the direct path of b by iteratively moving up the tree. Note that this
    // doesn't check the root node
    while curr_idx != root {
        if curr_idx == a {
            return true;
        }
        curr_idx = node_parent(curr_idx, num_leaves);
    }

    // If a is the root, then it's everybody's ancestor. Otherwise, we couldn't find a in b's
    // direct path, so it's not an ancestor
    a == root
}

/// Computes the index of the sibling of a given node. The sibling of the root is the root.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_sibling(idx: usize, num_leaves: usize) -> usize {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(idx < num_nodes_in_tree(num_leaves));

    // Recall that the left and right children of xyz...0111...1 are xyz...0011...1 and
    // xyz...1011...1, respectively. The former is less than the initial index, and the latter is
    // greater. So left is smaller, right is greater.
    let parent = node_parent(idx, num_leaves);
    if idx < parent {
        // We were on the left child, so return the right
        node_right_child(parent, num_leaves)
    } else if idx > parent {
        // We were on the right child, so return the left
        node_left_child(parent)
    } else {
        // We're at the root, so return the root
        parent
    }
}

/// Returns an iterator for the path up the tree `i_1, i_2, ..., i_n` where `i_1` is the the given
/// starting node and `i_n` is a child of the root node.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `start_idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_direct_path(start_idx: usize, num_leaves: usize) -> impl Iterator<Item = usize> {
    assert!(num_leaves > 0 && num_leaves <= MAX_LEAVES);
    assert!(start_idx < num_nodes_in_tree(num_leaves));

    // Start the direct path on the the given node. Since we loop inside DirectPathIter until
    // parent == root, this will be an empty iterator if we're the root node (since the parent of
    // the root is the root)
    DirectPathIter {
        num_leaves,
        successive_parent: start_idx,
    }
}

/// Returns an iterator for the path up the tree `i_1, i_2, ..., i_n` where `i_1` is the the given
/// starting node and `i_n` is the root node. This is called "extended" because direct paths do not
/// contain the root node. The extended direct path of a singleton tree is just
/// 1 node long.
///
/// Panics: when `num_leaves == 0` or `num_leaves > MAX_LEAVES` or
/// `start_idx >= num_nodes_in_tree(num_leaves)`
pub(crate) fn node_extended_direct_path(
    start_idx: usize,
    num_leaves: usize,
) -> impl Iterator<Item = usize> {
    let root = std::iter::once(root_idx(num_leaves));
    node_direct_path(start_idx, num_leaves).chain(root)
}

/// An iterator for direct paths
struct DirectPathIter {
    num_leaves: usize,
    successive_parent: usize,
}

impl Iterator for DirectPathIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        // If we're not at the root, return where we are, then move up one level
        if self.successive_parent != root_idx(self.num_leaves) {
            let ret = self.successive_parent;
            self.successive_parent = node_parent(self.successive_parent, self.num_leaves);

            Some(ret)
        } else {
            None
        }
    }
}
