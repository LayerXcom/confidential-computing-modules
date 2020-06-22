#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol

cd core

echo `cargo --version`
echo "Start building core components."

make DEBUG=1 FEATURES=ERC20
rm -rf ../example/erc20/bin && cp -rf bin/ ../example/erc20/bin/

echo "Testing core components..."
cd host
RUST_BACKTRACE=1 cargo test -- --nocapture

cd ../../example/erc20/server
echo "Build server."
RUST_BACKTRACE=1 RUST_LOG=debug cargo build

echo "Build in root dir."
cd ../../
RUST_BACKTRACE=1 RUST_LOG=debug cargo build
