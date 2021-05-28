use pgx::*;

extension_sql!(
    r#"
    CREATE AGGREGATE AVG (EncInteger)
    (
        sfunc = encinteger_avg_state_func,
        stype = EncAvgState,
        finalfunc = encinteger_avg_final_func,
        initcond = 'init_enc_avg_state()'
    );
    "#
);
