//! Intermediate states while calculating aggregation.
//!
//! Concrete calculation on receiving next field value should be hidden inside enclave.

mod enc_avg_state;

pub use enc_avg_state::EncAvgState;
