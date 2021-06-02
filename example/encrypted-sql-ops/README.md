# encrypted-sql-ops

A PostgreSQL extension to:

- encrypt column values.
- runs operations (`+`, `SUM`, for example) for the encrypted columns directly.

Plain data are visible only to data holders (who executes DML) and SGX Enclave. Tables have encrypted values and encryption key is hidden inside SGX.

## Getting started

This extension is developed using [`pgx`](https://github.com/zombodb/pgx), which provides highly useful toolkit to develop PostgreSQL extensions in Rust.

Docker image with `pgx` and compiled enclave library is available.

```bash
host> cd anonify
host> docker run -u `id -u`:`id -g` --device /dev/sgx/enclave --env-file .env -e IS_DEBUG=false -v `pwd`:/home/anonify-dev/anonify --rm -it anonify.azurecr.io/encrypted-sql-ops-pg:latest

container> cargo pgx run pg13
```

And then issue SQLs:

```sql
DROP TABLE IF EXISTS t;

DROP EXTENSION IF EXISTS encrypted_sql_ops;
CREATE EXTENSION encrypted_sql_ops;

CREATE TABLE t (c_plain INTEGER, c_enc ENCINTEGER);

INSERT INTO t (c_plain, c_enc) VALUES (1, ENCINTEGER_FROM(1)), (2, ENCINTEGER_FROM(2)), (3, ENCINTEGER_FROM(3)), (4, ENCINTEGER_FROM(4));

SELECT c_plain, c_enc from t;

 c_plain |                          c_enc
---------+------------------------------------------------------------
       1 | [149,3,227,162,36,90,43,228,60,152,116,237,254,27,237,158]
       2 | [47,58,132,191,44,135,127,49,101,67,11,162,75,124,183,161]
       3 | [126,143,247,147,31,14,139,6,210,47,6,69,103,35,253,43]
(3 rows)
-- c_enc's value may differ by encryption key

SELECT AVG(c_plain), AVG(c_enc) from t;

       AVG(c_plain) |     AVG(c_enc)
--------------------+--------------------
 2.5000000000000000 | 2.5
(1 rows)
```
