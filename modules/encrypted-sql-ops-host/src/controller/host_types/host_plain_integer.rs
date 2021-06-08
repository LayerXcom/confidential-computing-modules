//! Input from host.

use frame_host::ecall_controller::HostInput;

/// Plain-text representation in Rust of SQL INTEGER.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct HostPlainInteger {
    integer: i32,
}

impl HostInput for HostPlainInteger {}

impl HostPlainInteger {
    /// Constructor
    pub fn new(integer: i32) -> Self {
        Self { integer }
    }

    /// Get raw representation
    pub fn to_i32(&self) -> i32 {
        self.integer
    }
}
