mod func;
mod typ;

pub use typ::IntegerAvgState;

use pgx::*;

extension_sql!(
    r#"
    CREATE AGGREGATE MYAVG (integer)
    (
        sfunc = integer_avg_state_func,
        stype = IntegerAvgState,
        finalfunc = integer_avg_final_func,
        initcond = '{"sum": 0, "n": 0}'
    );
    "#
);
