#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[macro_use]
extern crate lazy_static;
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;
#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

use anonify_runtime::{
    prelude::*,
    state_type::*,
};
use crate::localstd::vec::Vec;
use anonify_common::UserAddress;
use codec::{Encode, Decode};

lazy_static! {
    pub static ref MAX_MEM_SIZE: usize = max_size();

    // 85 = user_address(20bytes) + lock_param(32bytes) + mem_id(8bytes) + iv(12bytes)
    // 1 bytes: base padding to represent a empty vec
    pub static ref CIPHERTEXT_SIZE: usize = *MAX_MEM_SIZE + 85 + 1;
}

impl_mem!{
    0, "Balance", Address => U64;
    1, "Balance2", Address => U64;
    // 2, "TotalSupply", U64;
}

impl_runtime!{
    #[fn_id=0]
    pub fn constructor(
        self,
        sender: UserAddress,
        total_supply: U64
    ) {
        let init = update!(sender, "Balance", total_supply);

        insert![init]
    }

    #[fn_id=1]
    pub fn transfer(
        self,
        sender: UserAddress,
        target: UserAddress,
        amount: U64
    ) {
        let my_balance = self.get::<U64>(&sender, "Balance")?;
        let target_balance = self.get::<U64>(&target, "Balance")?;

        ensure!(my_balance > amount, "You don't have enough balance.");

        let my_update = my_balance - amount;
        let target_update = target_balance + amount;

        let my = update!(sender, "Balance", my_update);
        let target = update!(target, "Balance", target_update);

        insert![my, target]
    }
}
