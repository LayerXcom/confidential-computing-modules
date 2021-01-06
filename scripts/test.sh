#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
ANONIFY_ROOT=/root/anonify

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
solc -o contract-build --bin --abi --optimize --overwrite contracts/Anonify.sol

cd frame/types
cargo build

# Generate each signed.so and measurement.txt

echo "Integration testing..."
cd ${ANONIFY_ROOT}/scripts
export ENCLAVE_PKG_NAME=secret_backup
make DEBUG=1 ENCLAVE_DIR=example/secret-backup/enclave
export ENCLAVE_PKG_NAME=erc20
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave
export BACKUP=disable
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave

#
# Integration Tests
#

# Module Tests

cd ${ANONIFY_ROOT}/tests/integration
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -- --nocapture

# ERC20 Application Tests

cd ${ANONIFY_ROOT}/example/erc20/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -- --nocapture

# Secret Backup Application Tests

export ENCLAVE_PKG_NAME=secret_backup
unset BACKUP
cd ${ANONIFY_ROOT}/example/secret-backup/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_backup_path_secret -- --nocapture

#
# Unit Tests
#

echo "Unit testing..."
export ENCLAVE_PKG_NAME=units
export BACKUP=disable
cd ${ANONIFY_ROOT}/scripts
make DEBUG=1 TEST=1 ENCLAVE_DIR=tests/units/enclave

cd ${ANONIFY_ROOT}
RUST_BACKTRACE=1 RUST_LOG=debug TEST=1 cargo test -p unit-tests-host -p anonify-eth-driver -p frame-runtime -- --nocapture

# Compile Checks

export ANONIFY_URL=http://172.28.1.1:8080
./scripts/build-cli.sh
