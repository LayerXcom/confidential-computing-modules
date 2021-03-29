use super::executor::CommandExecutor;
use super::plaintext::CommandPlaintext;
use anonify_ecall_types::*;
use anyhow::anyhow;
use frame_common::{
    crypto::{AccountId, Sha256},
    state_types::StateType,
    AccessPolicy,
};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, time};
use log::debug;

/// A message sender that encrypts commands
#[derive(Debug, Clone, Default)]
pub struct CommandByTreeKemSender<AP: AccessPolicy> {
    command_plaintext: CommandPlaintext<AP>,
    user_id: Option<AccountId>,
}

impl<AP> EnclaveEngine for CommandByTreeKemSender<AP>
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
            .encrypt_with_treekem(group_key, max_mem_size)?;

        let msg = Sha256::hash_for_attested_treekem_tx(
            &ciphertext.encode(),
            roster_idx,
            ciphertext.generation(),
            ciphertext.epoch(),
        );

        let st5 = time::SystemTime::now();
        debug!("########## st5: {:?}", st5);
        let enclave_sig = enclave_context.sign(msg.as_bytes())?;
        let command_output = output::Command::new(
            CommandCiphertext::TreeKem(ciphertext),
            enclave_sig.0,
            enclave_sig.1,
        );

        Ok(command_output)
    }
}

/// A message receiver that decrypt commands and make state transition
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CommandByTreeKemReceiver<AP> {
    ecall_input: input::InsertCiphertext,
    ap: PhantomData<AP>,
}

impl<AP> EnclaveEngine for CommandByTreeKemReceiver<AP>
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
        let treekem_ciphertext = match self.ecall_input.ciphertext() {
            CommandCiphertext::TreeKem(ciphertext) => ciphertext,
            _ => return Err(anyhow!("CommandCiphertext is not for treekem")),
        };

        let roster_idx = treekem_ciphertext.roster_idx() as usize;
        let msg_gen = treekem_ciphertext.generation();

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
            CommandExecutor::<R, C, AP>::decrypt_with_treekem(treekem_ciphertext, group_key)?;
        if let Some(cmds) = decrypted_cmds {
            let rt11 = std::time::SystemTime::now();
            debug!("########## rt11: {:?}", rt11);
            // Since the command data is valid for the error at the time of state transition,
            // `user_counter` must be verified and incremented before the state transition.
            enclave_context.verify_user_counter_increment(cmds.my_account_id(), cmds.counter())?;
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
