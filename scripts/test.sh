#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/.."
solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol

cd scripts

echo `cargo --version`
echo "Start building core components."

# Generate a `enclave.signed.so` in `$HOME/.anonify`
make DEBUG=1

echo "Testing core components..."
cd ../tests/integration
RUST_BACKTRACE=1 cargo test -- --nocapture

# cd ../../example/erc20/server
# echo "Build server."
# RUST_BACKTRACE=1 RUST_LOG=debug cargo build

# echo "Build in root dir."
# cd ../../
# RUST_BACKTRACE=1 RUST_LOG=debug cargo build
