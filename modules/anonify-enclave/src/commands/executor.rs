use super::plaintext::CommandPlaintext;
use crate::error::Result;
use anyhow::anyhow;
use frame_common::{
    crypto::AccountId,
    state_types::{NotifyState, ReturnState, StateType, UpdatedState, UserCounter},
    AccessPolicy, TreeKemCiphertext,
};
use frame_runtime::traits::*;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, vec::Vec};

/// Command data which make state update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecutor<R: RuntimeExecutor<CTX>, CTX: ContextOps<S = StateType>, AP> {
    my_account_id: AccountId,
    #[serde(deserialize_with = "R::C::deserialize")]
    call_kind: R::C,
    counter: UserCounter,
    phantom: PhantomData<CTX>,
    ap: PhantomData<AP>,
}

impl<R, CTX, AP> CommandExecutor<R, CTX, AP>
where
    R: RuntimeExecutor<CTX, S = StateType>,
    CTX: ContextOps<S = StateType>,
    AP: AccessPolicy,
{
    pub fn new(my_account_id: AccountId, command_plaintext: CommandPlaintext<AP>) -> Result<Self> {
        let call_kind = R::C::new(
            command_plaintext.cmd_name(),
            command_plaintext.runtime_params.clone(),
        )?;

        Ok(CommandExecutor {
            my_account_id,
            call_kind,
            counter: command_plaintext.counter(),
            phantom: PhantomData,
            ap: PhantomData,
        })
    }

    pub fn encrypt<GK: GroupKeyOps>(
        &self,
        key: &GK,
        max_mem_size: usize,
    ) -> Result<TreeKemCiphertext> {
        // Add padding to fix the ciphertext size of all state types.
        // The padding works for fixing the ciphertext size so that
        // other people cannot distinguish what state is encrypted based on the size.
        fn append_padding(buf: &mut Vec<u8>, max_mem_size: usize) {
            let padding_size = max_mem_size - buf.len();
            let padding = vec![0u8; padding_size];
            buf.extend_from_slice(&padding);
        }

        let mut buf = bincode::serialize(&self).unwrap(); // must not fail
        append_padding(&mut buf, max_mem_size);
        key.encrypt(buf).map_err(Into::into)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    /// Only if the TEE belongs to the group, you can receive ciphertext and decrypt it,
    /// otherwise do nothing.
    pub fn state_transition(
        self,
        ctx: CTX,
    ) -> Result<(
        impl Iterator<Item = UpdatedState<StateType>>,
        impl Iterator<Item = Option<NotifyState>>,
    )> {
        let stf_res = self.stf_call(ctx)?;
        Ok((stf_res.0.into_iter(), stf_res.1.into_iter()))
    }

    pub fn decrypt<GK: GroupKeyOps>(
        ciphertext: &TreeKemCiphertext,
        key: &mut GK,
    ) -> Result<Option<Self>> {
        match key.decrypt(ciphertext)? {
            Some(plaintext) => CommandExecutor::decode(&plaintext[..]).map(Some),
            None => Ok(None),
        }
    }

    fn stf_call(
        self,
        ctx: CTX,
    ) -> Result<(Vec<UpdatedState<StateType>>, Vec<Option<NotifyState>>)> {
        let res = R::new(ctx).execute(self.call_kind, self.my_account_id)?;

        match res {
            ReturnState::Updated(updates) => Ok(updates),
            ReturnState::Get(_) => Err(anyhow!(
                "Calling state transition function, but the called function is for getting state."
            )
            .into()),
        }
    }

    pub fn my_account_id(&self) -> AccountId {
        self.my_account_id
    }

    pub fn counter(&self) -> UserCounter {
        self.counter
    }
}
