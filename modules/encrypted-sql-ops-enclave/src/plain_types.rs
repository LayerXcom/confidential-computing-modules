//! Plain data types read/written only inside enclave.

mod plain_avg_state;
mod plain_integer;

pub use plain_avg_state::PlainAvgState;
pub use plain_integer::PlainInteger;
