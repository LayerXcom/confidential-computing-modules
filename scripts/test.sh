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

# Testings

echo "Integration testing..."
export ENCLAVE_PKG_NAME=erc20
cd ${ANONIFY_ROOT}/scripts
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave

cd ${ANONIFY_ROOT}/tests/integration
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -- --nocapture

cd ${ANONIFY_ROOT}/example/erc20/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_deploy_post -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_multiple_messages -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_skip_invalid_event -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_node_recovery -- --nocapture
sleep 1
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_join_group_then_handshake -- --nocapture

export ENCLAVE_PKG_NAME=secret_backup
cd ${ANONIFY_ROOT}/scripts
make DEBUG=1 ENCLAVE_DIR=example/secret-backup/enclave

cd ${ANONIFY_ROOT}/example/secret-backup/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_backup_path_secret -- --nocapture

echo "Unit testing..."
export ENCLAVE_PKG_NAME=units
cd ${ANONIFY_ROOT}/scripts
make DEBUG=1 TEST=1 ENCLAVE_DIR=tests/units/enclave

cd ${ANONIFY_ROOT}
RUST_BACKTRACE=1 RUST_LOG=debug TEST=1 cargo test -p unit-tests-host -p anonify-eth-driver -p frame-runtime -- --nocapture

# Buildings

export ANONIFY_URL=http://172.28.1.1:8080
./scripts/build-cli.sh

echo "Building ERC20 server..."
cd example/erc20/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo build

echo "Building secret-backup server..."
cd ../../secret-backup/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo build
