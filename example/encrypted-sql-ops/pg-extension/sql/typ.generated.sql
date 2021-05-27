CREATE TYPE encinteger;
CREATE OR REPLACE FUNCTION encinteger_in(cstring) RETURNS encinteger IMMUTABLE STRICT PARALLEL SAFE LANGUAGE C AS 'MODULE_PATHNAME', 'encinteger_in_wrapper';
CREATE OR REPLACE FUNCTION encinteger_out(encinteger) RETURNS cstring IMMUTABLE STRICT PARALLEL SAFE LANGUAGE C AS 'MODULE_PATHNAME', 'encinteger_out_wrapper';
CREATE TYPE encinteger (
                                INTERNALLENGTH = variable,
                                INPUT = encinteger_in,
                                OUTPUT = encinteger_out,
                                STORAGE = extended
                            );
CREATE TYPE avgstate;
CREATE OR REPLACE FUNCTION avgstate_in(cstring) RETURNS avgstate IMMUTABLE STRICT PARALLEL SAFE LANGUAGE C AS 'MODULE_PATHNAME', 'avgstate_in_wrapper';
CREATE OR REPLACE FUNCTION avgstate_out(avgstate) RETURNS cstring IMMUTABLE STRICT PARALLEL SAFE LANGUAGE C AS 'MODULE_PATHNAME', 'avgstate_out_wrapper';
CREATE TYPE avgstate (
                                INTERNALLENGTH = variable,
                                INPUT = avgstate_in,
                                OUTPUT = avgstate_out,
                                STORAGE = extended
                            );
