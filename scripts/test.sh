#!/bin/bash

set -eu

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
SGX_MODE=HW

echo "Start building core components."
make DEBUG=1

cd host
cargo test -- --nocapture