//! Input from host.

use frame_host::ecall_controller::HostOutput;

/// Plain-text representation in Rust of SQL REAL.
#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
pub struct HostPlainReal(f32);

impl HostOutput for HostPlainReal {}

impl From<f32> for HostPlainReal {
    fn from(f: f32) -> Self {
        Self(f)
    }
}

impl From<HostPlainReal> for f32 {
    fn from(h: HostPlainReal) -> Self {
        h.0
    }
}
