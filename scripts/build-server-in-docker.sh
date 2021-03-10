#!/bin/bash

set -e

source /root/.docker_bashrc
export PATH=~/.cargo/bin:$PATH
export SGX_MODE=HW
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
export STATE_RUNTIME_URL=172.16.0.3:8080
export ETH_URL=http://172.16.0.2:8545
export ANONYMOUS_ASSET_ABI_PATH="../../build/Anonify.abi"

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD

echo "Start building core components."

if [ "x$1" == "x--release" ]; then
    make FEATURES=ERC20
    rm -rf ../example/erc20/bin && cp -rf bin/ ../example/erc20/bin/ && cd ../example/erc20/server

    echo "Build artifacts in release mode, with optimizations."
    cargo build --release
    exit
fi

make DEBUG=1 FEATURES=ERC20
# enclave.signed.so is need to initialize enclave.
rm -rf ../example/erc20/bin && cp -rf bin/ ../example/erc20/bin/ && cd ../

solc -o contract-build --bin --abi --optimize --overwrite ethereum/contracts/Anonify.sol
cd example/erc20/server

echo "Build artifacts in debug mode."
RUST_BACKTRACE=1 RUST_LOG=debug cargo build
