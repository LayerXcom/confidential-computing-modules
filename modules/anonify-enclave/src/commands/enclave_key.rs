use super::executor::CommandExecutor;
use super::plaintext::CommandPlaintext;
use super::MAX_MEM_SIZE;
use anonify_ecall_types::cmd::FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD;
use anonify_ecall_types::cmd::SEND_COMMAND_ENCLAVE_KEY_CMD;
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
use std::marker::PhantomData;

/// A message sender that encrypts commands
#[derive(Debug, Clone)]
pub struct CommandByEnclaveKeySender<'c, C, R, AP: AccessPolicy> {
    command_plaintext: CommandPlaintext<AP>,
    enclave_context: &'c C,
    user_id: Option<AccountId>,
    _p: PhantomData<R>,
}

impl<'c, C, R, AP> StateRuntimeEnclaveUseCase<'c, C> for CommandByEnclaveKeySender<'c, C, R, AP>
where
    C: ContextOps<S = StateType> + Clone,
    R: RuntimeExecutor<C, S = StateType>,
    AP: AccessPolicy,
{
    type EI = input::Command;
    type EO = output::Command;
    const ENCLAVE_USE_CASE_ID: u32 = SEND_COMMAND_ENCLAVE_KEY_CMD;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        let buf = enclave_context.decrypt(enclave_input.ciphertext())?;
        let command_plaintext = serde_json::from_slice(&buf[..])?;

        Ok(Self {
            command_plaintext,
            enclave_context,
            user_id: enclave_input.user_id(),
            _p: PhantomData::default(),
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

    fn run(self) -> anyhow::Result<Self::EO> {
        let my_roster_idx = self.enclave_context.my_roster_idx() as u32;
        let pubkey = self.enclave_context.enclave_encryption_key()?;
        let my_account_id = self.command_plaintext.access_policy().into_account_id();

        let mut csprng = SgxRng::new()?;
        let ciphertext =
            CommandExecutor::<R, C, AP>::new(my_account_id, self.command_plaintext)?
                .encrypt_with_enclave_key(&mut csprng, pubkey, MAX_MEM_SIZE, my_roster_idx)?;

        let msg = Sha256::hash_for_attested_enclave_key_tx(&ciphertext.encode(), my_roster_idx);
        let enclave_sig = self.enclave_context.sign(msg.as_bytes())?;
        let command_output = output::Command::new(
            CommandCiphertext::EnclaveKey(ciphertext),
            enclave_sig.0,
            enclave_sig.1,
        );

        Ok(command_output)
    }
}

/// A message receiver that decrypt commands and make state transition
#[derive(Debug, Clone)]
pub struct CommandByEnclaveKeyReceiver<'c, C, R, AP> {
    enclave_input: input::InsertCiphertext,
    enclave_context: &'c C,
    _p: PhantomData<(R, AP)>,
}

impl<'c, C, R, AP> StateRuntimeEnclaveUseCase<'c, C> for CommandByEnclaveKeyReceiver<'c, C, R, AP>
where
    C: ContextOps<S = StateType> + Clone,
    R: RuntimeExecutor<C, S = StateType>,
    AP: AccessPolicy,
{
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;
    const ENCLAVE_USE_CASE_ID: u32 = FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self {
            enclave_input,
            enclave_context,
            _p: PhantomData::default(),
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// NOTE: Since this operation is stateful, you need to be careful about the order of processing, considering the possibility of processing failure.
    /// 1. Verify the order of transactions for each State Runtime node (verify_state_counter_increment)
    /// 2. Verify the order of transactions for each user (verify_user_counter_increment)
    /// 3. State transitions
    fn run(self) -> anyhow::Result<Self::EO> {
        let ciphertext: &SodiumCiphertext = match self.enclave_input.ciphertext() {
            CommandCiphertext::EnclaveKey(ciphertext) => ciphertext.encrypted_state(),
            _ => return Err(anyhow!("CommandCiphertext is not for enclave_key")),
        };

        // Even if group_key's ratchet operations and state transitions fail, state_counter must be incremented so it doesn't get stuck.
        self.enclave_context
            .verify_state_counter_increment(self.enclave_input.state_counter())?;

        let mut output = output::ReturnNotifyState::default();
        let enclave_decryption_key = self.enclave_context.enclave_decryption_key()?;
        let decrypted_cmds = CommandExecutor::<R, C, AP>::decrypt_with_enclave_key(
            ciphertext,
            &enclave_decryption_key,
        )?;

        // Since the command data is valid for the error at the time of state transition,
        // `user_counter` must be verified and incremented before the state transition.
        self.enclave_context.verify_user_counter_increment(
            decrypted_cmds.my_account_id(),
            decrypted_cmds.counter(),
        )?;
        // Even if an error occurs in the state transition logic here, there is no problem because the state of `app_keychain` is consistent.
        let state_iter = decrypted_cmds.state_transition(self.enclave_context.clone())?;

        if let Some(notify_state) = self
            .enclave_context
            .update_state(state_iter.0, state_iter.1)
        {
            let json = serde_json::to_vec(&notify_state)?;
            let bytes = bincode::serialize(&json[..])?;
            output.update(bytes);
        }

        Ok(output)
    }
}
