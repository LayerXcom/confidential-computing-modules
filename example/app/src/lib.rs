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

    // TODO: How 120bytes is calculated
    // 85 bytes: the size of base state without inner state
    // 1 bytes: base padding to represent a empty vec
    // 4*3 bytes: generaion, roster_idx, epoch for treekem
    pub static ref CIPHERTEXT_SIZE: usize = *MAX_MEM_SIZE + 120;
}

#[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, PartialOrd)]
struct CustomType {
    address: UserAddress,
    balance: U64,
}

impl_mem! {
    (0, "Balance", Address => U64)
}
// impl_mem! {
//     (1, "TotalSupply", U64)
// }

impl_runtime!{
    #[fn_id=0]
    pub fn constructor(
        self,
        sender: UserAddress,
        total_supply: U64
    ) {
        let sender_balance = update!(sender, "Balance", total_supply);

        insert![sender_balance]
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
