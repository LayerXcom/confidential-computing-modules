#![cfg(feature = "backup-enable")]
use crate::error::Result;
use crate::controller::host_input;
use crate::controller::*;
use frame_host::ecall_controller::EcallController;
use sgx_types::sgx_enclave_id_t;

#[derive(Debug, Default, Clone)]
pub struct SecretBackup;

impl SecretBackup {
    pub fn backup(&self, eid: sgx_enclave_id_t, ecall_cmd: u32) -> Result<()> {
        let input = host_input::Backup::new();
        let _ = BackupController::run(input, ecall_cmd, eid)?;
        Ok(())
    }

    pub fn recover(&self, eid: sgx_enclave_id_t, ecall_cmd: u32) -> Result<()> {
        let input = host_input::Recover::new();
        let _ = RecoverController::run(input, ecall_cmd, eid)?;
        Ok(())
    }
}
