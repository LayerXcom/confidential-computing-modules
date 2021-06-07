#![cfg(feature = "backup-enable")]

use crate::enclave_key::DEC_KEY_FILE_NAME;
use anonify_ecall_types::*;
use anyhow::{anyhow, Result};
use frame_common::state_types::StateType;
use frame_enclave::StateRuntimeEnclaveUseCase;
use frame_mra_tls::key_vault::request::{
    BackupPathSecretRequestBody, BackupPathSecretsRequestBody, RecoverPathSecretsRequestBody,
};
use frame_runtime::traits::*;
use frame_sodium::SealedEnclaveDecryptionKey;
use frame_treekem::PathSecret;
use std::vec::Vec;

/// A PathSecret Backupper
#[derive(Debug, Clone, Default)]
pub struct PathSecretsBackupper;

impl StateRuntimeEnclaveUseCase for PathSecretsBackupper {
    type EI = input::Empty;
    type EO = output::Empty;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    fn run<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let store_path_secrets = enclave_context.store_path_secrets();
        // retrieve local path_secrets IDs
        let ids = store_path_secrets.get_all_path_secret_ids()?;
        let roster_idx = (&*enclave_context.read_group_key()).my_roster_idx();

        // backup path_secrets to key-vault server
        let mut backup_path_secrets: Vec<BackupPathSecretRequestBody> = vec![];
        for id in ids {
            let eps = store_path_secrets.load_from_local_filesystem(&id)?;
            let ps = PathSecret::try_from_importing(eps.clone())?;
            let backup_path_secret = BackupPathSecretRequestBody::new(
                ps.as_bytes().to_vec(),
                eps.epoch(),
                roster_idx,
                id,
            );
            backup_path_secrets.push(backup_path_secret);
        }

        enclave_context
            .manually_backup_path_secrets(BackupPathSecretsRequestBody::new(backup_path_secrets))?;

        Ok(output::Empty::default())
    }
}

/// A PathSecret Recoverer
#[derive(Debug, Clone, Default)]
pub struct PathSecretsRecoverer;

impl StateRuntimeEnclaveUseCase for PathSecretsRecoverer {
    type EI = input::Empty;
    type EO = output::Empty;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    fn run<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        // fetch path_secrets from key-vault server
        let group_key = &*enclave_context.read_group_key();
        let roster_idx = group_key.my_roster_idx();
        let recover_request = RecoverPathSecretsRequestBody::new(roster_idx);
        let recovered_path_secrets =
            enclave_context.manually_recover_path_secrets(recover_request)?;

        // save path_secrets to own file system
        for rps in recovered_path_secrets {
            let path_secret = PathSecret::from(rps.path_secret());
            let eps = path_secret
                .clone()
                .try_into_exporting(rps.epoch(), rps.id())?;
            enclave_context
                .store_path_secrets()
                .save_to_local_filesystem(&eps)?;
        }
        Ok(output::Empty::default())
    }
}

/// A EnclaveKey Backupper
#[derive(Debug, Clone, Default)]
pub struct EnclaveKeyBackupper;

impl StateRuntimeEnclaveUseCase for EnclaveKeyBackupper {
    type EI = input::Empty;
    type EO = output::Empty;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    fn run<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        enclave_context.backup_enclave_key()?;
        Ok(output::Empty::default())
    }
}

/// A EnclaveKey Recoverer
#[derive(Debug, Clone, Default)]
pub struct EnclaveKeyRecoverer;

impl StateRuntimeEnclaveUseCase for EnclaveKeyRecoverer {
    type EI = input::Empty;
    type EO = output::Empty;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    fn run<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        // fetch path_secrets from key-vault server
        let dec_key = enclave_context.recover_enclave_key()?;

        // save path_secrets to own file system
        let encoded = dec_key.try_into_sealing()?;
        let sealed =
            SealedEnclaveDecryptionKey::decode(&encoded).map_err(|e| anyhow!("{:?}", e))?;

        let store_dec_key = enclave_context.store_enclave_dec_key();
        store_dec_key.save_to_local_filesystem(&sealed, DEC_KEY_FILE_NAME)?;

        Ok(output::Empty::default())
    }
}
