//! Input/Output types of enclave side.

mod enclave_enc_avg_state;
mod enclave_enc_avg_state_with_next;
mod enclave_enc_integer;
mod enclave_plain_integer;

pub use enclave_enc_avg_state::EnclaveEncAvgState;
pub use enclave_enc_avg_state_with_next::EnclaveEncAvgStateWithNext;
pub use enclave_enc_integer::EnclaveEncInteger;
pub use enclave_plain_integer::EnclavePlainInteger;
