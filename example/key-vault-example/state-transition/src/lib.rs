#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;

use frame_runtime::prelude::*;

pub const MAX_MEM_SIZE: usize = 5000;

impl_memory! {
    (0, "Balance", U64),
    (1, "Approved", Approved),
    (2, "TotalSupply", U64),
    (3, "Owner", AccountId)
}

impl_runtime! {
    #[fn_id=0]
    pub fn construct(
        self,
        sender: AccountId,
        total_supply: U64
    ) {
        let owner_account_id = update!(*OWNER_ACCOUNT_ID, "Owner", sender);
        let sender_balance = update!(sender, "Balance", total_supply);
        let total_supply = update!(*OWNER_ACCOUNT_ID, "TotalSupply", total_supply);

        return_update![owner_account_id, sender_balance, total_supply]
    }
}
