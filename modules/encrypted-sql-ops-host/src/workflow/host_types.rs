//! Input/Output types from/to host.
//! Basically all of them should be encrypted.

mod host_empty;
mod host_enc_avg_state;
mod host_enc_integer;
mod host_plain_integer;

pub use host_empty::HostEmpty;
pub use host_enc_avg_state::{HostInputEncAvgState, HostOutputEncAvgState};
pub use host_enc_integer::HostEncInteger;
pub use host_plain_integer::HostPlainInteger;
