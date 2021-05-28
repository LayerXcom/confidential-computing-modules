//! Input/Output types from/to host.
//! Basically all of them should be encrypted.

mod host_enc_integer;
mod host_plain_integer;

pub use host_enc_integer::HostEncInteger;
pub use host_plain_integer::HostPlainInteger;
