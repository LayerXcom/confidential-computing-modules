#![cfg(feature = "backup-enable")]
use crate::error::Result;
use crate::workflow::host_input;
use crate::workflow::*;
use frame_host::engine::HostEngine;
use sgx_types::sgx_enclave_id_t;

#[derive(Debug, Default, Clone)]
pub struct SecretBackup;

impl SecretBackup {
    pub fn all_backup_to(&self, eid: sgx_enclave_id_t, ecall_cmd: u32) -> Result<()> {
        let input = host_input::BackupPathSecretAll::new(ecall_cmd);
        let _ = BackupPathSecretAllWorkflow::exec(input, eid)?;
        Ok(())
    }

    pub fn all_backup_from(&self, eid: sgx_enclave_id_t, ecall_cmd: u32) -> Result<()> {
        let input = host_input::RecoverPathSecretAll::new(ecall_cmd);
        let _ = RecoverPathSecretAllWorkflow::exec(input, eid)?;
        Ok(())
    }
}
