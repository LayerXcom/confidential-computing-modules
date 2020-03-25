#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

mod application;
mod group_state;
pub mod handshake;
mod ratchet_tree;
mod tree_math;
mod crypto;
#[cfg(debug_assertions)]
mod test_utils;

pub use crate::application::{AppKeyChain, AppMsg};
pub use crate::group_state::{GroupState, Handshake};

#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    pub use application::tests::*;
    pub use crypto::ecies::tests::*;
}
