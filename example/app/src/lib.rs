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
    (0, "Balance", Address => U64)
    // (1, "TotalSupply", U64)
}

impl_runtime!{
    #[fn_id=0]
    pub fn constructor(
        self,
        sender: UserAddress,
        total_supply: U64
    ) {
        let sender_balance = update!(sender, "Balance", total_supply);
        let init = update!("TotalSupply", total_supply);

        insert![sender_balance, init]
    }

    #[fn_id=1]
    pub fn transfer(
        self,
        sender: UserAddress,
        recipient: UserAddress,
        amount: U64
    ) {
        let sender_balance = self.get_map::<U64>(sender, "Balance")?;
        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;

        ensure!(sender_balance > amount, "transfer amount exceeds balance.");

        let sender_update = update!(sender, "Balance", sender_balance - amount);
        let recipient_update = update!(recipient, "Balance", recipient_balance + amount);

        insert![sender_update, recipient_update]
    }
}
