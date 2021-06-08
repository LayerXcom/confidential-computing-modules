use anonify_ecall_types::*;
use anyhow::{anyhow, Result};
use frame_common::{crypto::Sha256, state_types::StateType};
use frame_enclave::StateRuntimeEnclaveUseCase;
#[cfg(feature = "backup-enable")]
use frame_mra_tls::key_vault::request::BackupPathSecretRequestBody;
use frame_runtime::traits::*;
use frame_treekem::handshake::HandshakeParams;

/// A update handshake sender
#[derive(Debug, Clone, Default)]
pub struct HandshakeSender;

impl StateRuntimeEnclaveUseCase for HandshakeSender {
    type EI = input::Empty;
    type EO = output::ReturnHandshake;

    fn new<C>(_enclave_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run<C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        let group_key = &*enclave_context.read_group_key();
        let (handshake, path_secret) = group_key.create_handshake()?;
        let epoch = handshake.prior_epoch();
        let id = handshake.hash();
        let export_path_secret = path_secret.clone().try_into_exporting(epoch, id.as_ref())?;
        enclave_context
            .store_path_secrets()
            .save_to_local_filesystem(&export_path_secret)?;
        let export_handshake = handshake.clone().into_export();

        #[cfg(feature = "backup-enable")]
        {
            let backup_path_secret = BackupPathSecretRequestBody::new(
                path_secret.as_bytes().to_vec(),
                epoch,
                handshake.roster_idx(),
                id.as_ref().to_vec(),
            );
            enclave_context.backup_path_secret(backup_path_secret)?;
        }

        let msg = Sha256::hash_for_attested_treekem_tx(
            &export_handshake.encode(),
            handshake.roster_idx(),
            0,         // processing handshake reset generation
            epoch + 1, // handshaked next epoch should be counted
        );
        let sig = enclave_context.sign(msg.as_bytes())?;
        let enclave_sig = sig.0;
        let recovery_id = sig.1;

        Ok(output::ReturnHandshake::new(
            export_handshake,
            enclave_sig,
            recovery_id,
        ))
    }
}

/// A handshake receiver
#[derive(Debug, Clone)]
pub struct HandshakeReceiver<'c, C> {
    enclave_input: input::InsertHandshake,
    enclave_context: &'c C,
}

impl<'c, C> StateRuntimeEnclaveUseCase<'c, C> for HandshakeReceiver<'c, C>
where
    C: ContextOps<S = StateType> + Clone,
{
    type EI = input::InsertHandshake;
    type EO = output::Empty;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self {
            enclave_input,
            enclave_context,
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn run(self) -> Result<Self::EO> {
        let group_key = &mut *self.enclave_context.write_group_key();
        let handshake = HandshakeParams::decode(&self.enclave_input.handshake().handshake()[..])
            .map_err(|_| anyhow!("HandshakeParams::decode Error"))?;

        // Even if `process_handshake` fails, state_counter must be incremented so it doesn't get stuck.
        self.enclave_context
            .verify_state_counter_increment(self.enclave_input.state_counter())?;
        group_key.process_handshake(
            enclave_context.store_path_secrets(),
            &handshake,
            #[cfg(feature = "backup-enable")]
            |ps_id, roster_idx| C::recover_path_secret(self.enclave_context, ps_id, roster_idx),
        )?;

        Ok(output::Empty::default())
    }
}
