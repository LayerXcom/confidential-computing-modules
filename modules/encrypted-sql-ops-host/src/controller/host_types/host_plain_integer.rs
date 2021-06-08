//! Input from host.

use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclavePlainInteger;

use super::host_enc_integer::HostEncInteger;

/// Plain-text representation in Rust of SQL INTEGER.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct HostPlainInteger {
    pub(super) integer: i32,
}

impl HostInput for HostPlainInteger {}

impl HostPlainInteger {
    /// Constructor
    pub fn new(integer: i32) -> Self {
        Self { integer }
    }
}
