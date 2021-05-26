#![cfg(feature = "backup-enable")]
use crate::error::Result;
use crate::workflow::host_input;
use crate::workflow::*;
use frame_host::engine::HostEngine;
use sgx_types::sgx_enclave_id_t;

#[derive(Debug, Default, Clone)]
pub struct SecretBackup;

impl SecretBackup {
    pub fn backup(&self, eid: sgx_enclave_id_t, ecall_cmd: u32) -> Result<()> {
        let input = host_input::Backup::new(ecall_cmd);
        let _ = BackupWorkflow::exec(input, eid)?;
        Ok(())
    }

    pub fn recover(&self, eid: sgx_enclave_id_t, ecall_cmd: u32) -> Result<()> {
        let input = host_input::Recover::new(ecall_cmd);
        let _ = RecoverWorkflow::exec(input, eid)?;
        Ok(())
    }
}
