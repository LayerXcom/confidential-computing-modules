use crate::State;
use crate::state_type::*;
use crate::localstd::{
    boxed::Box,
    string::String,
    vec::Vec,
};
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
}

impl_runtime!{
    #[fn_id=0]
    pub fn constructor(
        self,
        sender: UserAddress,
        total_supply: U64
    ) -> Result<Vec<UpdatedState<StateType>>,codec::Error> {
        let init = UpdatedState::new(sender, "Balance", total_supply.into());

        Ok(vec![init])
    }

    #[fn_id=1]
    pub fn transfer(
        self,
        sender: UserAddress,
        target: UserAddress,
        amount: U64
    ) -> Result<Vec<UpdatedState<StateType>>,codec::Error> {
        let my_balance = self.db.get::<U64>(&sender, "Balance")?;
        let target_balance = self.db.get::<U64>(&target, "Balance")?;

        if my_balance < amount {
            return Err("You don't have enough balance.".into());
        }
        let my_update = my_balance - amount;
        let other_update = target_balance + amount;

        let my = UpdatedState::new(sender, "Balance", my_update.into());
        let other = UpdatedState::new(target, "Balance", other_update.into());

        Ok(vec![my, other])
    }
}
