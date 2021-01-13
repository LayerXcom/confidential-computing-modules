#![cfg(feature = "backup-enable")]

use anonify_config::DEFAULT_LOCAL_PATH_SECRETS_DIR;
use anonify_io_types::*;
use anyhow::Result;
use frame_common::{
    crypto::{BackupPathSecret, RecoverAllRequest},
    state_types::StateType,
};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_treekem::{PathSecret, StorePathSecrets};
use key_vault_enclave::get_local_path_secret_ids;
use std::{env, vec::Vec};

/// A PathSecret Backupper
#[derive(Debug, Clone)]
pub struct PathSecretBackupper;

impl EnclaveEngine for PathSecretBackupper {
    type EI = input::BackupPathSecretAll;
    type EO = output::Empty;

    fn handle<R, C>(
        _ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        // retrieve local path_secrets IDs
        let path_secrets_dir = env::var("LOCAL_PATH_SECRETS_DIR")
            .unwrap_or(format!("{}", DEFAULT_LOCAL_PATH_SECRETS_DIR));
        let ids = get_local_path_secret_ids(path_secrets_dir.clone())?;

        let store_path_secrets = StorePathSecrets::new(path_secrets_dir);
        let group_key = &*enclave_context.read_group_key();
        let roster_idx = group_key.my_roster_idx();

        // backup path_secrets to key-vault server
        let mut backup_path_secrets: Vec<BackupPathSecret> = vec![];
        for id in ids {
            let eps = store_path_secrets.load_from_local_filesystem(&id)?;
            let ps = PathSecret::try_from_importing(eps.clone())?;
            let backup_path_secret =
                BackupPathSecret::new(ps.as_bytes().to_vec(), eps.epoch(), roster_idx, id);
            backup_path_secrets.push(backup_path_secret);
        }

        enclave_context.manually_backup_path_secrets_all(backup_path_secrets)?;

        Ok(output::Empty::default())
    }
}

/// A PathSecret Recoverer
#[derive(Debug, Clone)]
pub struct PathSecretRecoverer;

impl EnclaveEngine for PathSecretRecoverer {
    type EI = input::RecoverPathSecretAll;
    type EO = output::Empty;

    fn handle<R, C>(
        _ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        // fetch path_secrets from key-vault server
        let group_key = &*enclave_context.read_group_key();
        let roster_idx = group_key.my_roster_idx();
        let recover_all_request = RecoverAllRequest::new(roster_idx);
        let recovered_path_secrets =
            enclave_context.manually_recover_path_secrets_all(recover_all_request)?;

        // save path_secrets to own file system
        let path_secrets_dir = env::var("LOCAL_PATH_SECRETS_DIR")
            .unwrap_or(format!("{}", DEFAULT_LOCAL_PATH_SECRETS_DIR));
        let store_path_secrets = StorePathSecrets::new(path_secrets_dir);

        for rps in recovered_path_secrets {
            let path_secret = PathSecret::from(rps.path_secret());
            let eps = path_secret
                .clone()
                .try_into_exporting(rps.epoch(), rps.id())?;
            store_path_secrets.save_to_local_filesystem(&eps)?;
        }
        Ok(output::Empty::default())
    }
}
