//! Plain data types read/written only inside enclave.

pub(crate) mod plain_avg_state;

mod plain_integer;
mod plain_real;

pub use plain_avg_state::PlainAvgState;
pub use plain_integer::PlainInteger;
pub use plain_real::PlainReal;
