use super::executor::CommandExecutor;
use super::plaintext::CommandPlaintext;
use anonify_ecall_types::*;
use anyhow::anyhow;
use frame_common::{
    crypto::{AccountId, Sha256},
    state_types::StateType,
    AccessPolicy,
};
use frame_enclave::StateRuntimeEnclaveUseCase;
use frame_runtime::traits::*;
use frame_sodium::{rng::SgxRng, SodiumCiphertext};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// A message sender that encrypts commands
#[derive(Debug, Clone, Default)]
pub struct CommandByEnclaveKeySender<AP: AccessPolicy> {
    command_plaintext: CommandPlaintext<AP>,
    user_id: Option<AccountId>,
}

impl<AP> StateRuntimeEnclaveUseCase for CommandByEnclaveKeySender<AP>
where
    AP: AccessPolicy,
{
    type EI = input::Command;
    type EO = output::Command;

    fn new<C>(enclave_input: Self::EI, enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let buf = enclave_context.decrypt(enclave_input.ciphertext())?;
        let command_plaintext = serde_json::from_slice(&buf[..])?;

        Ok(Self {
            command_plaintext,
            user_id: enclave_input.user_id(),
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

    fn run<C>(self, enclave_context: &C, max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let my_roster_idx = enclave_context.my_roster_idx() as u32;
        let pubkey = enclave_context.enclave_encryption_key()?;
        let my_account_id = self.command_plaintext.access_policy().into_account_id();

        let mut csprng = SgxRng::new()?;
        let ciphertext =
            CommandExecutor::<R, C, AP>::new(my_account_id, self.command_plaintext)?
                .encrypt_with_enclave_key(&mut csprng, pubkey, max_mem_size, my_roster_idx)?;

        let msg = Sha256::hash_for_attested_enclave_key_tx(&ciphertext.encode(), my_roster_idx);
        let enclave_sig = enclave_context.sign(msg.as_bytes())?;
        let command_output = output::Command::new(
            CommandCiphertext::EnclaveKey(ciphertext),
            enclave_sig.0,
            enclave_sig.1,
        );

        Ok(command_output)
    }
}

/// A message receiver that decrypt commands and make state transition
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CommandByEnclaveKeyReceiver<AP> {
    enclave_input: input::InsertCiphertext,
    ap: PhantomData<AP>,
}

impl<AP> StateRuntimeEnclaveUseCase for CommandByEnclaveKeyReceiver<AP>
where
    AP: AccessPolicy,
{
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;

    fn new<C>(enclave_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self {
            enclave_input,
            ap: PhantomData,
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// NOTE: Since this operation is stateful, you need to be careful about the order of processing, considering the possibility of processing failure.
    /// 1. Verify the order of transactions for each State Runtime node (verify_state_counter_increment)
    /// 2. Verify the order of transactions for each user (verify_user_counter_increment)
    /// 3. State transitions
    fn run<C>(self, enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let ciphertext: &SodiumCiphertext = match self.enclave_input.ciphertext() {
            CommandCiphertext::EnclaveKey(ciphertext) => ciphertext.encrypted_state(),
            _ => return Err(anyhow!("CommandCiphertext is not for enclave_key")),
        };

        // Even if group_key's ratchet operations and state transitions fail, state_counter must be incremented so it doesn't get stuck.
        enclave_context.verify_state_counter_increment(self.enclave_input.state_counter())?;

        let mut output = output::ReturnNotifyState::default();
        let enclave_decryption_key = enclave_context.enclave_decryption_key()?;
        let decrypted_cmds = CommandExecutor::<R, C, AP>::decrypt_with_enclave_key(
            ciphertext,
            &enclave_decryption_key,
        )?;

        // Since the command data is valid for the error at the time of state transition,
        // `user_counter` must be verified and incremented before the state transition.
        enclave_context.verify_user_counter_increment(
            decrypted_cmds.my_account_id(),
            decrypted_cmds.counter(),
        )?;
        // Even if an error occurs in the state transition logic here, there is no problem because the state of `app_keychain` is consistent.
        let state_iter = decrypted_cmds.state_transition(enclave_context.clone())?;

        if let Some(notify_state) = enclave_context.update_state(state_iter.0, state_iter.1) {
            let json = serde_json::to_vec(&notify_state)?;
            let bytes = bincode::serialize(&json[..])?;
            output.update(bytes);
        }

        Ok(output)
    }
}
