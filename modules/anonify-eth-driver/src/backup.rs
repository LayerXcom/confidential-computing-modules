#![cfg(feature = "backup-enable")]
use crate::workflow::host_input;
use crate::workflow::*;
use crate::error::Result;
use frame_host::engine::HostEngine;
use sgx_types::sgx_enclave_id_t;

#[derive(Debug, Default, Clone)]
pub struct SecretBackup;

impl SecretBackup {
    pub fn all_backup_to(&self, eid: sgx_enclave_id_t) -> Result<()> {
        let input = host_input::BackupPathSecretAll::default();
        let _ = BackupPathSecretAllWorkflow::exec(input, eid)?;
        Ok(())
    }

    pub fn all_backup_from(&self, eid: sgx_enclave_id_t) -> Result<()> {
        let input = host_input::RecoverPathSecretAll::default();
        let _ = RecoverPathSecretAllWorkflow::exec(input, eid)?;
        Ok(())
    }
}
