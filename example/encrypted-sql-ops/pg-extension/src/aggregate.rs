use pgx::*;

extension_sql!(
    r#"
    CREATE AGGREGATE AVG (EncInteger)
    (
        sfunc = encinteger_avg_state_func,
        stype = AvgState,
        finalfunc = encinteger_avg_final_func,
        initcond = '{"sum": 0, "n": 0}'
    );
    "#
);
