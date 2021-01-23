#![cfg(feature = "backup-enable")]

use anonify_ecall_types::*;
use anyhow::Result;
use frame_common::{
    crypto::{BackupPathSecret, RecoverAllRequest},
    state_types::StateType,
};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use frame_treekem::PathSecret;
use std::vec::Vec;

/// A PathSecret Backupper
#[derive(Debug, Clone, Default)]
pub struct PathSecretBackupper;

impl EnclaveEngine for PathSecretBackupper {
    type EI = input::BackupPathSecretAll;
    type EO = output::Empty;

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let store_path_secrets = enclave_context.store_path_secrets();
        // retrieve local path_secrets IDs
        let ids = store_path_secrets.get_all_path_secret_ids()?;
        let roster_idx = (&*enclave_context.read_group_key()).my_roster_idx();

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
#[derive(Debug, Clone, Default)]
pub struct PathSecretRecoverer;

impl EnclaveEngine for PathSecretRecoverer {
    type EI = input::RecoverPathSecretAll;
    type EO = output::Empty;

    fn handle<R, C>(self, enclave_context: &C, _max_mem_size: usize) -> Result<Self::EO>
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
