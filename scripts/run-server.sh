#!/bin/bash

set -eu

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
SGX_MODE=HW
ANONIFY_URL=172.18.0.3:8080
ETH_URL=172.18.0.2:8545

echo "Start building core components."
make

rm -rf ../example/bin
cp -r bin/ ../example/bin/
cd ../example/server

if [ -n "$1" ]; then
    if [ "$1" == "--release" ]; then
        echo "Build artifacts in release mode, with optimizations."
        cargo build --release
        exit
    fi
fi

echo "Build artifacts in debug mode."
RUST_LOG=debug cargo build