#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

mod application;
mod group_state;
mod handshake;
mod ratchet_tree;
mod tree_math;
mod crypto;
#[cfg(debug_assertions)]
mod test_utils;

#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    pub use application::test::*;
}
