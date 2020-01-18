use crate::{
    state::{UserState, StateValue, Current, Next},
    error::Result,
    kvs::{SigVerificationKVS, MEMORY_DB},
};
use anonify_common::{UserAddress, State, stf::Value};
use ed25519_dalek::{PublicKey, Signature};
use std::{
    vec::Vec,
    io::{self, Write, Read, Error, ErrorKind},
    ops::{Add, Sub},
    convert::TryInto,
};

pub trait AnonymousAssetSTF: Sized {
    type S: State;

    fn init(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        amount: Self::S,
    ) -> Result<UserState<Self::S, Next>>;

    fn transfer(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        target: UserAddress,
        amount: Self::S,
    ) -> Result<(UserState<Self::S, Next>, UserState<Self::S, Next>)>;
}

impl<S: State> AnonymousAssetSTF for UserState<S, Current> {
    type S = Value;

    fn init(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        total_supply: Self::S,
    ) -> Result<UserState<Self::S, Next>> {
        let address = UserAddress::from_sig(&msg, &sig, &from);
        let state: UserState<Self::S, Next> = UserState::new(address, total_supply)?;

        Ok(state)
    }

    // TODO: Generalize state transition function so that developer can define their own stf.
    // TODO: Must have secure error handling so that part of updated data cannot be stored into mem db and avoiding inconsistency.
    /// Calcurate state transition results. This function always has no side-effect.
    fn transfer(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        target: UserAddress,
        amount: Self::S,
    ) -> Result<(UserState<Self::S, Next>, UserState<Self::S, Next>)> {
        let my_addr = UserAddress::from_sig(&msg, &sig, &from);
        let my_value = MEMORY_DB.get(&my_addr);
        let my_current_state_value = StateValue::<Self::S, Current>::from_dbvalue(my_value.clone())?;
        let my_current_balance = my_current_state_value.inner_state();

        // TODO: Return as error
        assert!(amount < *my_current_balance);

        let my_current_state = UserState::from_address_and_db_value(my_addr, my_value)?;
        let my_updated: UserState<Self::S, Next> = my_current_state
            .update_inner_state(*my_current_balance - amount).try_into()?;

        // TODO
        let other_value = MEMORY_DB.get(&target);
        let other_current_state_value = StateValue::<Self::S, Current>::from_dbvalue(other_value.clone())?;
        let other_current_balance = other_current_state_value.inner_state();
        let other_current_state = UserState::from_address_and_db_value(target, other_value)?;
        let other_updated: UserState<Self::S, Next> = other_current_state
            .update_inner_state(*other_current_balance + amount).try_into()?;

        Ok((my_updated, other_updated))
    }
}
