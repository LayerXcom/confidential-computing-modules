use crate::{
    state::{UserState, CurrentNonce, NextNonce},
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
    ) -> Result<UserState<Self::S, NextNonce>>;

    fn transfer(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        target: UserAddress,
        amount: Self::S,
    ) -> Result<(UserState<Self::S, NextNonce>, UserState<Self::S, NextNonce>)>;
}

impl<S: State> AnonymousAssetSTF for UserState<S, CurrentNonce> {
    type S = Value;

    fn init(
        from: PublicKey,
        sig: Signature,
        msg: &[u8],
        total_supply: Self::S,
    ) -> Result<UserState<Self::S, NextNonce>> {
        let address = UserAddress::from_sig(&msg, &sig, &from);
        let state: UserState<Self::S, NextNonce> = UserState::new(address, total_supply)?;

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
    ) -> Result<(UserState<Self::S, NextNonce>, UserState<Self::S, NextNonce>)> {
        let my_addr = UserAddress::from_sig(&msg, &sig, &from);
        let my_value = MEMORY_DB.get(&my_addr);
        let my_current_balance = UserState::<Self::S, _>::get_state_nonce_from_dbvalue(my_value.clone())?.0;

        // TODO: Return as error
        assert!(amount < my_current_balance);

        let my_current_state = UserState::from_address_and_db_value(my_addr, my_value)?;
        let my_updated: UserState<Self::S, NextNonce> = my_current_state
            .update_inner_state(my_current_balance - amount).try_into()?;

        // TODO
        let other_value = MEMORY_DB.get(&target);
        let other_current_balance = UserState::<Self::S, _>::get_state_nonce_from_dbvalue(other_value.clone())?.0;
        let other_current_state = UserState::from_address_and_db_value(target, other_value)?;
        let other_updated: UserState<Self::S, NextNonce> = other_current_state
            .update_inner_state(other_current_balance + amount).try_into()?;

        Ok((my_updated, other_updated))
    }
}
