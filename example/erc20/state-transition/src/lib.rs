#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;

use anonify_runtime::{
    prelude::*,
    state_type::*,
    traits::*,
};
use crate::localstd::{
    vec::Vec,
    collections::BTreeMap
};
use anonify_common::{UserAddress, OWNER_ADDRESS};
use codec::{Encode, Decode};

pub const MAX_MEM_SIZE: usize = 100;
pub const CIPHERTEXT_SIZE: usize = MAX_MEM_SIZE + 30;

impl_memory! {
    (0, "Balance", U64),
    (1, "Approved", Approved),
    (2, "TotalSupply", U64),
    (3, "Owner", UserAddress)
}

impl_runtime! {
    #[fn_id=0]
    pub fn construct(
        self,
        sender: UserAddress,
        total_supply: U64
    ) {
        let owner_address = update!(*OWNER_ADDRESS, "Owner", sender);
        let sender_balance = update!(sender, "Balance", total_supply);
        let total_supply = update!(*OWNER_ADDRESS, "TotalSupply", total_supply);

        insert![owner_address, sender_balance, total_supply]
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

    #[fn_id=2]
    pub fn approve(
        self,
        owner: UserAddress,
        spender: UserAddress,
        amount: U64
    ) {
        let owner_balance = self.get_map::<U64>(owner, "Balance")?;
        let mut owner_approved = self.get_map::<Approved>(owner, "Approved")?;

        ensure!(
            owner_approved.total() + amount <= owner_balance,
            "approving amount exceeds balance and already approved."
        );

        owner_approved.approve(spender, amount);
        let owner_approved_update = update!(owner, "Approved", owner_approved);
        insert![owner_approved_update]
    }

    #[fn_id=3]
    pub fn transfer_from(
        self,
        sender: UserAddress,
        owner: UserAddress,
        recipient: UserAddress,
        amount: U64
    ) {
        let owner_balance = self.get_map::<U64>(owner, "Balance")?;
        ensure!(
            amount <= owner_balance,
            "transferring amount exceeds owner's balance."
        );

        let mut owner_approved = self.get_map::<Approved>(owner, "Approved")?;
        let approved_amount = owner_approved.allowance(&sender)
            .ok_or(anyhow!("not enough amount approved."))?;
        ensure!(
            amount <= *approved_amount,
            "transferring amount exceeds approved amount of sender."
        );

        owner_approved.consume(sender, amount)?;
        let owner_approved_update = update!(owner, "Approved", owner_approved);

        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;

        let owner_balance_update = update!(owner, "Balance", owner_balance - amount);
        let recipient_balance_update = update!(recipient, "Balance", recipient_balance + amount);

        insert![owner_approved_update, owner_balance_update, recipient_balance_update]
    }

    #[fn_id=4]
    pub fn mint(
        self,
        executer: UserAddress,
        recipient: UserAddress,
        amount: U64
    ) {
        let owner_address = self.get_map::<UserAddress>(*OWNER_ADDRESS, "Owner")?;
        ensure!(executer == owner_address, "only owner can mint");

        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;
        let recipient_balance_update = update!(recipient, "Balance", recipient_balance + amount);

        let total_supply = self.get_map::<U64>(*OWNER_ADDRESS, "TotalSupply")?;
        let total_supply_update = update!(*OWNER_ADDRESS, "TotalSupply", total_supply + amount);

        insert![recipient_balance_update, total_supply_update]
    }

    #[fn_id=5]
    pub fn burn(
        self,
        sender: UserAddress,
        amount: U64
    ) {
        let balance = self.get_map::<U64>(sender, "Balance")?;
        ensure!(balance >= amount, "not enough balance to burn");
        let balance_update = update!(sender, "Balance", balance - amount);

        let total_supply = self.get_map::<U64>(*OWNER_ADDRESS, "TotalSupply")?;
        let total_supply_update = update!(*OWNER_ADDRESS, "TotalSupply", total_supply - amount);

        insert![balance_update, total_supply_update]
    }
}
