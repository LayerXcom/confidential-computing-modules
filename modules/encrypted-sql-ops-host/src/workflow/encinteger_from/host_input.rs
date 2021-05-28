//! Input from host.

use super::host_output;
use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::enclave_types::RawInteger as EnclaveRawInteger;

/// Raw represation in Rust of SQL INTEGER.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct RawInteger {
    integer: i32,
    ecall_cmd: u32,
}

impl HostInput for RawInteger {
    type EcallInput = EnclaveRawInteger;
    type HostOutput = host_output::EncIntegerWrapper;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((
            EnclaveRawInteger::from(self.integer),
            host_output::EncIntegerWrapper(None),
        ))
    }

    fn ecall_cmd(&self) -> u32 {
        self.ecall_cmd
    }
}

impl RawInteger {
    /// Constructor
    pub fn new(integer: i32, ecall_cmd: u32) -> Self {
        Self {
            integer, 
            ecall_cmd 
        }
    }
}
