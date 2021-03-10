use frame_runtime::prelude::*;

pub const MAX_MEM_SIZE: usize = 100;

impl_memory! {
    (0, "Balance", U64),
    (1, "Approved", Approved),
    (2, "TotalSupply", U64),
    (3, "Owner", AccountId)
}

impl_runtime! {
    pub fn construct(
        self,
        sender: AccountId,
        total_supply: U64
    ) {
        let owner_account_id = update!(*OWNER_ACCOUNT_ID, "Owner", sender, AccountId);
        let sender_balance = update!(sender, "Balance", total_supply, U64);
        let total_supply = update!(*OWNER_ACCOUNT_ID, "TotalSupply", total_supply, U64);

        return_update![owner_account_id, sender_balance, total_supply]
    }

    pub fn transfer(
        self,
        sender: AccountId,
        recipient: AccountId,
        amount: U64
    ) {
        env_logger::init();
        debug!("##### transfer");
        let sender_balance = self.get_map::<U64>(sender, "Balance")?;
        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;

        ensure!(sender_balance > amount, "transfer amount ({:?}) exceeds balance ({:?}).", amount, sender_balance);

        let sender_update = update!(sender, "Balance", sender_balance - amount, U64);
        let recipient_update = update!(recipient, "Balance", recipient_balance + amount, U64);

        return_update![sender_update, recipient_update]
    }

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
        let owner_approved_update = update!(owner, "Approved", owner_approved, Approved);
        return_update![owner_approved_update]
    }

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
        let owner_approved_update = update!(owner, "Approved", owner_approved, Approved);

        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;

        let owner_balance_update = update!(owner, "Balance", owner_balance - amount, U64);
        let recipient_balance_update = update!(recipient, "Balance", recipient_balance + amount, U64);

        return_update![owner_approved_update, owner_balance_update, recipient_balance_update]
    }

    pub fn mint(
        self,
        executer: AccountId,
        recipient: AccountId,
        amount: U64
    ) {
        let owner_account_id = self.get_map::<AccountId>(*OWNER_ACCOUNT_ID, "Owner")?;
        ensure!(executer == owner_account_id, "only owner can mint");

        let recipient_balance = self.get_map::<U64>(recipient, "Balance")?;
        let recipient_balance_update = update!(recipient, "Balance", recipient_balance + amount, U64);

        let total_supply = self.get_map::<U64>(*OWNER_ACCOUNT_ID, "TotalSupply")?;
        let total_supply_update = update!(*OWNER_ACCOUNT_ID, "TotalSupply", total_supply + amount, U64);

        return_update![recipient_balance_update, total_supply_update]
    }

    pub fn burn(
        self,
        sender: AccountId,
        amount: U64
    ) {
        let balance = self.get_map::<U64>(sender, "Balance")?;
        ensure!(balance >= amount, "not enough balance to burn");
        let balance_update = update!(sender, "Balance", balance - amount, U64);

        let total_supply = self.get_map::<U64>(*OWNER_ACCOUNT_ID, "TotalSupply")?;
        let total_supply_update = update!(*OWNER_ACCOUNT_ID, "TotalSupply", total_supply - amount, U64);

        return_update![balance_update, total_supply_update]
    }

    pub fn balance_of(
        self,
        caller: AccountId
    ) {
        let balance = self.get_map::<U64>(caller, "Balance")?;
        get_state![balance]
    }

    pub fn approved(
        self,
        caller: AccountId,
        spender: AccountId
    ) {
        let approved = self.get_map::<Approved>(caller, "Approved")?;
        get_state![approved.get(spender)]
    }

    pub fn total_supply(
        self,
        caller: AccountId
    ) {
        let total_supply = self.get_map::<U64>(*OWNER_ACCOUNT_ID, "TotalSupply")?;
        get_state![total_supply]
    }

    pub fn owner(
        self,
        caller: AccountId
    ) {
        let owner = self.get_map::<AccountId>(*OWNER_ACCOUNT_ID, "Owner")?;
        get_state![owner]
    }
}
