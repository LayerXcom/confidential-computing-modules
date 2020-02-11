#!/bin/bash

set -e

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
export SGX_MODE=HW

echo "Start building core components."

if [ "x$1" == "x--release" ]; then
    make
    rm -rf ../example/bin && cp -rf bin/ ../example/bin/ && cd ../example/server

    echo "Build artifacts in release mode, with optimizations."
    cargo run --release
    exit
fi

make DEBUG=1
rm -rf ../example/bin && cp -rf bin/ ../example/bin/ && cd ../

solc -o build --bin --abi --optimize --overwrite contracts/AnonymousAsset.sol
cd example/server

echo "Build artifacts in debug mode."
RUST_BACKTRACE=1 RUST_LOG=debug cargo run
