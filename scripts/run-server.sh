#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
export ANONIFY_URL=172.18.0.3:8080
export ETH_URL=http://172.18.0.2:8545
export ANONYMOUS_ASSET_ABI_PATH="../../build/Anonify.abi"

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD

echo "Start building core components."

if [ "x$1" == "x--release" ]; then
    make
    rm -rf ../example/bin && cp -rf bin/ ../example/bin/ && cd ../example/server

    echo "Build artifacts in release mode, with optimizations."
    cargo run --release
    exit
fi

make DEBUG=1
# enclave.signed.so is need to initialize enclave.
rm -rf ../example/bin && cp -rf bin/ ../example/bin/ && cd ../

solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol
cd example/server

echo "Build artifacts in debug mode."
RUST_BACKTRACE=1 RUST_LOG=debug cargo run
