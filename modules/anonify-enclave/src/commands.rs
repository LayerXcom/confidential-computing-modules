use crate::error::Result;
use anonify_ecall_types::*;
use anyhow::anyhow;
use codec::{Decode, Encode};
use frame_common::{
    crypto::{AccountId, Ciphertext, Sha256},
    state_types::{ReturnState, StateType, UpdatedState},
    traits::Hash256,
    AccessPolicy,
};
use frame_enclave::EnclaveEngine;
use frame_runtime::{traits::*, RuntimeCommand};
use frame_treekem::EciesCiphertext;
use std::{marker::PhantomData, string::ToString, vec::Vec};

/// A message sender that encrypts commands
#[derive(Debug, Clone, Default)]
pub struct MsgSender<AP: AccessPolicy, RC: RuntimeCommand> {
    ecall_input: input::Command<AP, RC>,
}

impl<AP, RC> EnclaveEngine for MsgSender<AP, RC>
where
    AP: AccessPolicy,
    RC: RuntimeCommand,
{
    type EI = EciesCiphertext;
    type EO = output::Command;

    fn decrypt<C>(ciphertext: Self::EI, enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let buf = enclave_context.decrypt(ciphertext)?;
        let ecall_input = input::Command::decode(&mut &buf[..]).map_err(|e| anyhow!("{:?}", e))?;
        Ok(Self { ecall_input })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        self.ecall_input.access_policy().verify()
    }

    fn handle<R, C>(self, enclave_context: &C, max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let roster_idx = group_key.my_roster_idx() as usize;
        // ratchet sender's app keychain per tx.
        group_key.sender_ratchet(roster_idx)?;

        let my_account_id = self.ecall_input.access_policy().into_account_id();
        let ciphertext = Commands::<R, C, AP, RC>::new(my_account_id, self.ecall_input)?
            .encrypt(group_key, max_mem_size)?;

        let msg = Sha256::hash(&ciphertext.encode());
        let enclave_sig = enclave_context.sign(msg.as_bytes())?;
        let command_output = output::Command::new(ciphertext, enclave_sig.0, enclave_sig.1);

        enclave_context.set_notification(my_account_id);

        Ok(command_output)
    }
}

/// A message receiver that decrypt commands and make state transition
#[derive(Encode, Decode, Debug, Clone, Default)]
pub struct MsgReceiver<AP, RC> {
    ecall_input: input::InsertCiphertext,
    ap: PhantomData<AP>,
    rc: PhantomData<RC>,
}

impl<AP, RC> EnclaveEngine for MsgReceiver<AP, RC>
where
    AP: AccessPolicy,
    RC: RuntimeCommand,
{
    type EI = input::InsertCiphertext;
    type EO = output::ReturnUpdatedState;

    fn decrypt<C>(ciphertext: Self::EI, enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        // TODO: decrypt
        Ok(Self {
            ecall_input: ciphertext,
            ap: PhantomData,
            rc: PhantomData,
        })
    }

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let roster_idx = self.ecall_input.ciphertext().roster_idx() as usize;
        let msg_gen = self.ecall_input.ciphertext().generation();

        // Since the sender's keychain has already ratcheted,
        // even if an error occurs in the state transition, the receiver's keychain also ratchet.
        // `receiver_ratchet` fails if
        //   1. Roster index is out of range of the keychain
        //   2. error occurs in HKDF
        //   3. the generation is over u32::MAX
        // In addition to these, `sync_ratchet` fails even if the receiver generation is larger than that of the sender
        // So if you run `sync_ratchet` first,
        // it will either succeed or both fail for the mutable `app_keychain`, so it will be atomic.
        group_key.sync_ratchet(roster_idx, msg_gen)?;
        group_key.receiver_ratchet(roster_idx)?;

        // Even if an error occurs in the state transition logic here, there is no problem because the state of `app_keychain` is consistent.
        let iter_op = Commands::<R, C, AP, RC>::state_transition(
            enclave_context.clone(),
            self.ecall_input.ciphertext(),
            group_key,
        )?;
        let mut output = output::ReturnUpdatedState::default();

        if let Some(updated_state_iter) = iter_op {
            if let Some(updated_state) = enclave_context.update_state(updated_state_iter) {
                output.update(updated_state);
            }
        }

        Ok(output)
    }
}

/// Command data which make state update
#[derive(Debug, Clone, Encode, Decode)]
pub struct Commands<R: RuntimeExecutor<CTX>, CTX: ContextOps, AP, RC> {
    my_account_id: AccountId,
    call_kind: R::C,
    phantom: PhantomData<CTX>,
    ap: PhantomData<AP>,
    rc: PhantomData<RC>,
}

impl<R, CTX, AP, RC> Commands<R, CTX, AP, RC>
where
    R: RuntimeExecutor<CTX>,
    CTX: ContextOps,
    AP: AccessPolicy,
    RC: RuntimeCommand,
{
    pub fn new(my_account_id: AccountId, ecall_input: input::Command<AP, RC>) -> Result<Self> {
        let call_kind = R::C::new(
            ecall_input.fn_name().to_string(),
            &ecall_input.runtime_command,
        )?;

        Ok(Commands {
            my_account_id,
            call_kind,
            phantom: PhantomData,
            ap: PhantomData,
            rc: PhantomData,
        })
    }

    pub fn encrypt<GK: GroupKeyOps>(&self, key: &GK, max_mem_size: usize) -> Result<Ciphertext> {
        // Add padding to fix the ciphertext size of all state types.
        // The padding works for fixing the ciphertext size so that
        // other people cannot distinguish what state is encrypted based on the size.
        fn append_padding(buf: &mut Vec<u8>, max_mem_size: usize) {
            let padding_size = max_mem_size - buf.len();
            let padding = vec![0u8; padding_size];
            buf.extend_from_slice(&padding);
        }

        let mut buf = self.encode();
        append_padding(&mut buf, max_mem_size);
        key.encrypt(buf).map_err(Into::into)
    }

    /// Only if the TEE belongs to the group, you can receive ciphertext and decrypt it,
    /// otherwise do nothing.
    pub fn state_transition<GK: GroupKeyOps>(
        ctx: CTX,
        ciphertext: &Ciphertext,
        group_key: &mut GK,
    ) -> Result<Option<impl Iterator<Item = UpdatedState<StateType>> + Clone>> {
        if let Some(commands) = Commands::<R, CTX, AP, RC>::decrypt(ciphertext, group_key)? {
            let state_iter = commands.stf_call(ctx)?.into_iter();

            return Ok(Some(state_iter));
        }

        Ok(None)
    }

    fn decrypt<GK: GroupKeyOps>(ciphertext: &Ciphertext, key: &mut GK) -> Result<Option<Self>> {
        match key.decrypt(ciphertext)? {
            Some(plaintext) => Commands::decode(&mut &plaintext[..])
                .map(Some)
                .map_err(Into::into),
            None => Ok(None),
        }
    }

    fn stf_call(self, ctx: CTX) -> Result<Vec<UpdatedState<StateType>>> {
        let res = R::new(ctx).execute(self.call_kind, self.my_account_id)?;

        match res {
            ReturnState::Updated(updates) => Ok(updates),
            ReturnState::Get(_) => Err(anyhow!(
                "Calling state transition function, but the called function is for getting state."
            )
            .into()),
        }
    }
}
