use crate::error::Result;
use anonify_ecall_types::*;
use anyhow::anyhow;
use frame_common::{
    crypto::{AccountId, Ciphertext, Sha256},
    state_types::{NotifyState, ReturnState, StateType, UpdatedState, UserCounter},
    AccessPolicy,
};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    string::{String, ToString},
    vec::Vec,
};
use log::debug;

/// A message sender that encrypts commands
#[derive(Debug, Clone, Default)]
pub struct CmdSender<AP: AccessPolicy> {
    command_plaintext: CommandPlaintext<AP>,
    user_id: Option<AccountId>,
}

impl<AP> EnclaveEngine for CmdSender<AP>
where
    AP: AccessPolicy,
{
    type EI = input::Command;
    type EO = output::Command;

    fn decrypt<C>(ecall_input: Self::EI, enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let buf = enclave_context.decrypt(ecall_input.ciphertext())?;
        let command_plaintext = serde_json::from_slice(&buf[..])?;

        Ok(Self {
            command_plaintext,
            user_id: ecall_input.user_id(),
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        if self.command_plaintext.access_policy().verify().is_err() {
            return Err(anyhow!("Failed to verify access policy"));
        }

        if let Some(user_id_for_verify) = self.user_id {
            let user_id = self.command_plaintext.access_policy().into_account_id();
            if user_id != user_id_for_verify {
                return Err(anyhow!(
                    "Invalid user_id. user_id in the ciphertext: {:?}, user_id for verification: {:?}",
                    user_id,
                    user_id_for_verify
                ));
            }
        }

        Ok(())
    }

    fn handle<R, C>(self, enclave_context: &C, max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let st2 = time::SystemTime::now();
        debug!("########## st2: {:?}", st2);
        let group_key = &mut *enclave_context.write_group_key();
        let roster_idx = group_key.my_roster_idx();

        let st3 = time::SystemTime::now();
        debug!("########## st3: {:?}", st3);
        // ratchet sender's app keychain per tx.
        group_key.sender_ratchet(roster_idx as usize)?;

        let my_account_id = self.command_plaintext.access_policy().into_account_id();

        let st4 = time::SystemTime::now();
        debug!("########## st4: {:?}", st4);
        let ciphertext = CommandExecutor::<R, C, AP>::new(my_account_id, self.command_plaintext)?
            .encrypt(group_key, max_mem_size)?;

        let msg = Sha256::hash_for_attested_tx(
            &ciphertext.encode(),
            roster_idx,
            ciphertext.generation(),
            ciphertext.epoch(),
        );

        let st5 = time::SystemTime::now();
        debug!("########## st5: {:?}", st5);
        let enclave_sig = enclave_context.sign(msg.as_bytes())?;
        let command_output = output::Command::new(ciphertext, enclave_sig.0, enclave_sig.1);

        Ok(command_output)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandPlaintext<AP: AccessPolicy> {
    #[serde(deserialize_with = "AP::deserialize")]
    pub access_policy: AP,
    pub runtime_params: serde_json::Value,
    pub cmd_name: String,
    pub counter: UserCounter,
}

impl<AP> Default for CommandPlaintext<AP>
where
    AP: AccessPolicy,
{
    fn default() -> Self {
        Self {
            access_policy: AP::default(),
            runtime_params: serde_json::Value::Null,
            cmd_name: String::default(),
            counter: UserCounter::default(),
        }
    }
}

impl<AP> CommandPlaintext<AP>
where
    AP: AccessPolicy,
{
    pub fn new(
        access_policy: AP,
        runtime_params: serde_json::Value,
        cmd_name: impl ToString,
        counter: UserCounter,
    ) -> Self {
        CommandPlaintext {
            access_policy,
            runtime_params,
            cmd_name: cmd_name.to_string(),
            counter,
        }
    }

    pub fn access_policy(&self) -> &AP {
        &self.access_policy
    }

    pub fn cmd_name(&self) -> &str {
        &self.cmd_name
    }

    pub fn counter(&self) -> UserCounter {
        self.counter
    }
}

/// A message receiver that decrypt commands and make state transition
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CmdReceiver<AP> {
    ecall_input: input::InsertCiphertext,
    ap: PhantomData<AP>,
}

impl<AP> EnclaveEngine for CmdReceiver<AP>
where
    AP: AccessPolicy,
{
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;

    fn decrypt<C>(ciphertext: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self {
            ecall_input: ciphertext,
            ap: PhantomData,
        })
    }

    /// NOTE: Since this operation is stateful, you need to be careful about the order of processing, considering the possibility of processing failure.
    /// 1. Verify the order of transactions for each State Runtime node (verify_state_counter_increment)
    /// 2. Ratchet keychains
    /// 3. Verify the order of transactions for each user (verify_user_counter_increment)
    /// 4. State transitions
    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let rt7 = std::time::SystemTime::now();
        debug!("########## rt7: {:?}", rt7);
        let group_key = &mut *enclave_context.write_group_key();
        let roster_idx = self.ecall_input.ciphertext().roster_idx() as usize;
        let msg_gen = self.ecall_input.ciphertext().generation();

        let rt8 = std::time::SystemTime::now();
        debug!("########## rt8: {:?}", rt8);
        // Even if group_key's ratchet operations and state transitions fail, state_counter must be incremented so it doesn't get stuck.
        enclave_context.verify_state_counter_increment(self.ecall_input.state_counter())?;

        let rt9 = std::time::SystemTime::now();
        debug!("########## rt9: {:?}", rt9);
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

        let rt10 = std::time::SystemTime::now();
        debug!("########## rt10: {:?}", rt10);
        let mut output = output::ReturnNotifyState::default();
        let decrypted_cmds =
            CommandExecutor::<R, C, AP>::decrypt(self.ecall_input.ciphertext(), group_key)?;
        if let Some(cmds) = decrypted_cmds {
            let rt11 = std::time::SystemTime::now();
            debug!("########## rt11: {:?}", rt11);
            // Since the command data is valid for the error at the time of state transition,
            // `user_counter` must be verified and incremented before the state transition.
            enclave_context.verify_user_counter_increment(cmds.my_account_id, cmds.counter)?;
            // Even if an error occurs in the state transition logic here, there is no problem because the state of `app_keychain` is consistent.
            let state_iter = cmds.state_transition(enclave_context.clone())?;

            let rt15 = std::time::SystemTime::now();
            debug!("########## rt15: {:?}", rt15);
            if let Some(notify_state) = enclave_context.update_state(state_iter.0, state_iter.1) {
                let json = serde_json::to_vec(&notify_state)?;
                let bytes = bincode::serialize(&json[..])?;
                output.update(bytes);
            }
        }

        Ok(output)
    }
}

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

    pub fn encrypt<GK: GroupKeyOps>(&self, key: &GK, max_mem_size: usize) -> Result<Ciphertext> {
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

    fn decrypt<GK: GroupKeyOps>(ciphertext: &Ciphertext, key: &mut GK) -> Result<Option<Self>> {
        match key.decrypt(ciphertext)? {
            Some(plaintext) => CommandExecutor::decode(&plaintext[..]).map(Some),
            None => Ok(None),
        }
    }

    fn stf_call(
        self,
        ctx: CTX,
    ) -> Result<(Vec<UpdatedState<StateType>>, Vec<Option<NotifyState>>)> {
        let rt12 = std::time::SystemTime::now();
        debug!("########## rt12: {:?}", rt12);
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
