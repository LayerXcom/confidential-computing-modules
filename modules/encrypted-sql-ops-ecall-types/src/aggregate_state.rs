//! Intermediate states while calculating aggregation.
//!
//! Concrete calculation on receiving next field value should be hidden inside enclave.

mod avg;

pub use avg::AvgState;
