#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;
#[cfg(feature = "std")]
use serde_std as serde;

use frame_runtime::prelude::*;
use serde::{Deserialize, Serialize};

pub mod cmd;

pub const MAX_MEM_SIZE: usize = 100;
pub const CIPHERTEXT_SIZE: usize = MAX_MEM_SIZE + 30;

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

    #[fn_id=1]
    pub fn transfer(
        self,
        sender: AccountId,
        recipient: AccountId,
        amount: U64
    ) {
        let sender_balance = self.get_map::<U64>(sender, "Balance")?;
        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;

        ensure!(sender_balance > amount, "transfer amount ({:?}) exceeds balance ({:?}).", amount, sender_balance);

        let sender_update = update!(sender, "Balance", sender_balance - amount);
        let recipient_update = update!(recipient, "Balance", recipient_balance + amount);

        return_update![sender_update, recipient_update]
    }

    #[fn_id=2]
    pub fn approve(
        self,
        owner: AccountId,
        spender: AccountId,
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
        return_update![owner_approved_update]
    }

    #[fn_id=3]
    pub fn transfer_from(
        self,
        sender: AccountId,
        owner: AccountId,
        recipient: AccountId,
        amount: U64
    ) {
        let owner_balance = self.get_map::<U64>(owner, "Balance")?;
        ensure!(
            amount <= owner_balance,
            "transferring amount exceeds owner's balance."
        );

        let mut owner_approved = self.get_map::<Approved>(owner, "Approved")?;
        let approved_amount = owner_approved.allowance(&sender)
            .ok_or_else(|| anyhow!("not enough amount approved."))?;
        ensure!(
            amount <= *approved_amount,
            "transferring amount exceeds approved amount of sender."
        );

        owner_approved.consume(sender, amount)?;
        let owner_approved_update = update!(owner, "Approved", owner_approved);

        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;

        let owner_balance_update = update!(owner, "Balance", owner_balance - amount);
        let recipient_balance_update = update!(recipient, "Balance", recipient_balance + amount);

        return_update![owner_approved_update, owner_balance_update, recipient_balance_update]
    }

    #[fn_id=4]
    pub fn mint(
        self,
        executer: AccountId,
        recipient: AccountId,
        amount: U64
    ) {
        let owner_account_id = self.get_map::<AccountId>(*OWNER_ACCOUNT_ID, "Owner")?;
        ensure!(executer == owner_account_id, "only owner can mint");

        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;
        let recipient_balance_update = update!(recipient, "Balance", recipient_balance + amount);

        let total_supply = self.get_map::<U64>(*OWNER_ACCOUNT_ID, "TotalSupply")?;
        let total_supply_update = update!(*OWNER_ACCOUNT_ID, "TotalSupply", total_supply + amount);

        return_update![recipient_balance_update, total_supply_update]
    }

    #[fn_id=5]
    pub fn burn(
        self,
        sender: AccountId,
        amount: U64
    ) {
        let balance = self.get_map::<U64>(sender, "Balance")?;
        ensure!(balance >= amount, "not enough balance to burn");
        let balance_update = update!(sender, "Balance", balance - amount);

        let total_supply = self.get_map::<U64>(*OWNER_ACCOUNT_ID, "TotalSupply")?;
        let total_supply_update = update!(*OWNER_ACCOUNT_ID, "TotalSupply", total_supply - amount);

        return_update![balance_update, total_supply_update]
    }

    #[fn_id=6]
    pub fn balance_of(
        self,
        caller: AccountId
    ) {
        let balance = self.get_map::<U64>(caller, "Balance")?;
        get_state![balance]
    }

    #[fn_id=7]
    pub fn approved(
        self,
        caller: AccountId
    ) {
        let approved = self.get_map::<Approved>(caller, "Approved")?;
        get_state![approved]
    }

    #[fn_id=8]
    pub fn total_supply(
        self,
        caller: AccountId
    ) {
        let total_supply = self.get_map::<U64>(*OWNER_ACCOUNT_ID, "TotalSupply")?;
        get_state![total_supply]
    }

    #[fn_id=9]
    pub fn owner(
        self,
        caller: AccountId
    ) {
        let owner = self.get_map::<AccountId>(*OWNER_ACCOUNT_ID, "Owner")?;
        get_state![owner]
    }
}
