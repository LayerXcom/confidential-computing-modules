#!/bin/bash

set -eu

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW

echo `cargo --version`
echo "Start building core components."

make DEBUG=1
rm -rf ../example/bin && cp -rf bin/ ../example/bin/ && cd ../example/server

echo "Testing core components..."
cd host
RUST_BACKTRACE=1 cargo test -- --nocapture

cd ../../example/server
echo "Build server."
RUST_BACKTRACE=1 RUST_LOG=debug cargo build

echo "Build in root dir."
cd ../../
RUST_BACKTRACE=1 RUST_LOG=debug cargo build
