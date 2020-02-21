#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
sleep 1

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
solc -o build --bin --abi --optimize --overwrite contracts/AnonymousAsset.sol

cp .env.template .env && cp example/server/.env.template example/server/.env

cd core

echo `cargo --version`
echo "Start building core components."

# sudo rm -rf bin/ lib/ enclave/target/ host/target/
# sudo rm -f enclave/Enclave_t.c enclave/Enclave_t.h enclave/Enclave_t.o enclave/enclave.so \
# host/Enclave_u.c host/Enclave_u.o host/Enclave_u.h host/libEnclave_u.a
make DEBUG=1
rm -rf ../example/bin && cp -rf bin/ ../example/bin/

echo "Testing core components..."
cd host
RUST_BACKTRACE=1 cargo test -- --nocapture

cd ../../example/server
echo "Build server."
# RUST_BACKTRACE=1 RUST_LOG=debug cargo build

echo "Build in root dir."
cd ../../
RUST_BACKTRACE=1 RUST_LOG=debug cargo build
