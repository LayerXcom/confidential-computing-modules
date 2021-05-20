#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
ANONIFY_ROOT=/root/anonify
ANONIFY_TAG=v0.5.11

#
# Setup Tests
#

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
if [ ! -d ${ANONIFY_ROOT}/anonify-contracts ]; then
    git clone --depth 1 -b $ANONIFY_TAG https://github.com/LayerXcom/anonify-contracts
else
    cd ${ANONIFY_ROOT}/anonify-contracts
    tag_id=`git show $ANONIFY_TAG | grep commit | cut -f 2 -d ' '`
    current_commit_id=`git rev-parse HEAD`
    if [ $tag_id = $current_commit_id ]; then
        echo "already cloned /anonify-contracts(skipped)"
    else
        echo "already exists /anonify-contracts directory, but doesn't match commit id with specified by tag"
        exit 1
    fi
fi

cd ${ANONIFY_ROOT}
solc -o contract-build --bin --abi --optimize --overwrite \
  anonify-contracts/contracts/AnonifyWithTreeKem.sol \
  anonify-contracts/contracts/AnonifyWithEnclaveKey.sol \
  anonify-contracts/contracts/Factory.sol

# Deploy a FACTORY Contract
cd ${ANONIFY_ROOT}/anonify-contracts/deployer
export FACTORY_CONTRACT_ADDRESS=$(cargo run factory)

cd ${ANONIFY_ROOT}/frame/types
cargo build

# Generate key-vault's signed.so and measurement.txt
echo "Integration testing..."
cd ${ANONIFY_ROOT}/scripts
export ENCLAVE_PKG_NAME=key_vault
make DEBUG=1 ENCLAVE_DIR=example/key-vault/enclave

#
# Unit Tests
#

env
echo "Unit testing..."
export ENCLAVE_PKG_NAME=units
cd ${ANONIFY_ROOT}/scripts
# make with backup disabled
make DEBUG=1 TEST=1 ENCLAVE_DIR=tests/units/enclave FEATURE_FLAGS="runtime_enabled"

cd ${ANONIFY_ROOT}
RUST_BACKTRACE=1 RUST_LOG=debug TEST=1 cargo test \
  -p unit-tests-host \
  -p frame-runtime \
  -p frame-retrier \
  -p frame-azure-client \
  -p frame-sodium -- --nocapture

#
# Tests for enclave key
#

# Integration Tests
export ENCLAVE_PKG_NAME=erc20
# make with backup disabled
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave FEATURE_FLAGS="runtime_enabled,enclave_key"
cd ${ANONIFY_ROOT}/tests/integration
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_enclave_key -- --nocapture

# ERC20 Application Tests

function exec_sr_enclave_key_node_tests() {
  for N in "$@"
  do
    cd ${ANONIFY_ROOT}/anonify-contracts/deployer
    cargo run anonify_ek "$FACTORY_CONTRACT_ADDRESS"
    cd ${ANONIFY_ROOT}/nodes/state-runtime/server

    RUST_BACKTRACE=1 RUST_LOG=debug cargo test "$N" -- --nocapture
    sleep 1
  done
}

exec_sr_enclave_key_node_tests test_health_check \
  test_enclave_key_evaluate_access_policy_by_user_id_field \
  test_enclave_key_multiple_messages \
  test_enclave_key_skip_invalid_event \
  test_enclave_key_node_recovery \
  test_enclave_key_join_group_then_handshake \
  test_enclave_key_duplicated_out_of_order_request_from_same_user

# Secret Backup Application Tests

cd ${ANONIFY_ROOT}/scripts
export ENCLAVE_PKG_NAME=erc20
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave

cd ${ANONIFY_ROOT}/nodes/key-vault
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_health_check -- --nocapture

function exec_kv_enclave_key_node_tests() {
  for N in "$@"
  do
    cd ${ANONIFY_ROOT}/anonify-contracts/deployer
    cargo run anonify_ek "$FACTORY_CONTRACT_ADDRESS"
    cd ${ANONIFY_ROOT}/nodes/key-vault

    RUST_BACKTRACE=1 RUST_LOG=debug cargo test "$N" -- --nocapture
    sleep 1
  done
}

exec_kv_enclave_key_node_tests test_health_check \
  test_enclave_key_backup

#
# Tests for treekem
#

# Integration Tests
cd ${ANONIFY_ROOT}/scripts
export ENCLAVE_PKG_NAME=erc20
# make with backup disabled
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave FEATURE_FLAGS="runtime_enabled,treekem"
cd ${ANONIFY_ROOT}/tests/integration
RUST_BACKTRACE=1 RUST_LOG=debug cargo test test_treekem --no-default-features -- --nocapture

# ERC20 Application Tests

function exec_sr_treekem_node_tests() {
  for N in "$@"
  do
    cd ${ANONIFY_ROOT}/anonify-contracts/deployer
    cargo run anonify_tk "$FACTORY_CONTRACT_ADDRESS"
    cd ${ANONIFY_ROOT}/nodes/state-runtime/server

    RUST_BACKTRACE=1 RUST_LOG=debug cargo test "$N" -- --nocapture
    sleep 1
  done
}

exec_sr_treekem_node_tests \
  test_treekem_evaluate_access_policy_by_user_id_field \
  test_treekem_multiple_messages \
  test_treekem_skip_invalid_event \
  test_treekem_join_group_then_handshake \
  test_treekem_duplicated_out_of_order_request_from_same_user

# Secret Backup Application Tests

cd ${ANONIFY_ROOT}/scripts
export ENCLAVE_PKG_NAME=erc20
make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave FEATURE_FLAGS="runtime_enabled,backup-enable,treekem"

function exec_kv_treekem_node_tests() {
  for N in "$@"
  do
    cd ${ANONIFY_ROOT}/anonify-contracts/deployer
    cargo run anonify_tk "$FACTORY_CONTRACT_ADDRESS"
    cd ${ANONIFY_ROOT}/nodes/key-vault

    RUST_BACKTRACE=1 RUST_LOG=debug cargo test "$N" -- --nocapture
    sleep 1
  done
}

exec_kv_treekem_node_tests \
  test_treekem_backup_path_secret \
  test_treekem_recover_without_key_vault \
  test_treekem_manually_backup_all \
  test_treekem_manually_recover_all

#
# Compile Checks
#

./scripts/build-cli.sh
cd ${ANONIFY_ROOT}/example/erc20/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo c
cd ${ANONIFY_ROOT}/example/key-vault/server
RUST_BACKTRACE=1 RUST_LOG=debug cargo c
cd ${ANONIFY_ROOT}/example/wallet
RUST_BACKTRACE=1 RUST_LOG=debug cargo c
