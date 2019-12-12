#!/bin/bash

set -eu

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
export SGX_MODE=HW
export ANONIFY_URL=172.18.0.3:8080
export ETH_URL=172.18.0.2:8545

echo "Start building core components."
make

cp -r bin/ ../example/bin/
cd ../example/server
RUST_LOG=debug cargo run --release