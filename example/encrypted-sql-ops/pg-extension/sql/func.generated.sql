-- ./src/func.rs:7:0
CREATE OR REPLACE FUNCTION "encinteger_from"("raw_integer" integer) RETURNS EncInteger STRICT LANGUAGE c AS 'MODULE_PATHNAME', 'encinteger_from_wrapper';
-- ./src/func.rs:18:0
CREATE OR REPLACE FUNCTION "encinteger_avg_state_func"("_internal_state" AvgState, "_next_data_value" EncInteger) RETURNS AvgState STRICT LANGUAGE c AS 'MODULE_PATHNAME', 'encinteger_avg_state_func_wrapper';
-- ./src/func.rs:23:0
CREATE OR REPLACE FUNCTION "encinteger_avg_final_func"("_internal_state" AvgState) RETURNS integer STRICT LANGUAGE c AS 'MODULE_PATHNAME', 'encinteger_avg_final_func_wrapper';
