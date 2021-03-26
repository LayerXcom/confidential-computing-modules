#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3

solc -o contract-build --bin --abi --optimize --overwrite ethereum/contracts/AnonifyWithTreeKem.sol ethereum/contracts/AnonifyWithEnclaveKey.sol ethereum/contracts/Factory.sol

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
echo $PWD

cd frame/types
cargo build

echo "Start building core components."
cd ../../scripts
if [ "x$1" == "x--release" ]; then
    make ENCLAVE_DIR=example/erc20/enclave

    echo "Build artifacts in release mode, with optimizations."
    cargo run --release
    exit
fi

make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave
# enclave.signed.so is need to initialize enclave.

cd ../example/erc20/server

echo "Build artifacts in debug mode."
RUST_BACKTRACE=1 RUST_LOG=debug cargo run
