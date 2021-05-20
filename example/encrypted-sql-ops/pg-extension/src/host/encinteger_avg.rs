mod error;
mod typ;

pub use typ::EncInteger;

pub(crate) use error::DecryptError;

use pgx::*;

extension_sql!(
    r#"
    CREATE AGGREGATE ENCAVG (EncInteger)
    (
        sfunc = encinteger_avg_state_func,
        stype = IntegerAvgState,
        finalfunc = encinteger_avg_final_func,
        initcond = '{"sum": 0, "n": 0}'
    );
    "#
);
