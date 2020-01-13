#!/bin/bash

set -eu

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
export SGX_MODE=SW

echo "Start building core components."

make DEBUG=1
rm -rf ../example/bin && cp -rf bin/ ../example/bin/ && cd ../example/server

echo "Build server."
RUST_BACKTRACE=1 RUST_LOG=debug cargo build

echo "Build in root dir."
cd ../../
RUST_BACKTRACE=1 RUST_LOG=debug cargo build
