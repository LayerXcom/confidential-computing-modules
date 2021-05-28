//! Input from host.

use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclavePlainInteger;

use super::host_output::HostEncInteger;

/// Plain-text representation in Rust of SQL INTEGER.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct HostPlainInteger {
    integer: i32,
    ecall_cmd: u32,
}

impl HostInput for HostPlainInteger {
    type EcallInput = EnclavePlainInteger;
    type HostOutput = HostEncInteger;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((
            EnclavePlainInteger::from(self.integer),
            HostEncInteger(None),
        ))
    }

    fn ecall_cmd(&self) -> u32 {
        self.ecall_cmd
    }
}

impl HostPlainInteger {
    /// Constructor
    pub fn new(integer: i32, ecall_cmd: u32) -> Self {
        Self { integer, ecall_cmd }
    }
}
