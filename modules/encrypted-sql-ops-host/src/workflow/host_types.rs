//! Input/Output types from/to host.
//! Basically all of them should be encrypted.

mod host_input_enc_avg_state;
mod host_output_enc_avg_state;
mod host_enc_avg_state_with_next;
mod host_enc_integer;
mod host_plain_integer;
mod host_plain_real;

pub use host_input_enc_avg_state::HostInputEncAvgState;
pub use host_output_enc_avg_state::HostOutputEncAvgState;
pub use host_enc_avg_state_with_next::HostEncAvgStateWithNext;
pub use host_enc_integer::HostEncInteger;
pub use host_plain_integer::HostPlainInteger;
pub use host_plain_real::HostPlainReal;
