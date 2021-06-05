#!/bin/bash
set -ex

# Prerequisite: cargo-pgx must be installed

id

export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."
export PJ_ROOT_DIR=$ANONIFY_ROOT
ANONIFY_TAG=v0.5.11

sudo chown anonify-dev:anonify-dev -R ~/{.rustup,.pgx}  # in case fixuid is too slow

# Generate signed.so and measurement.txt
echo "Integration testing..."
cd ${ANONIFY_ROOT}/scripts
export ENCLAVE_PKG_NAME=encrypted_sql_ops
make DEBUG=1 ENCLAVE_DIR=example/encrypted-sql-ops/enclave

# Integration Tests
cd ${ANONIFY_ROOT}/example/encrypted-sql-ops/pg-extension
USER=anonify-dev cargo pgx test pg13
