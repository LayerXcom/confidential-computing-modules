#!/bin/bash

set -e

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

cd "$ANONIFY_ROOT"
# TODO: Remove
export PATH="/opt/occlum/build/bin:/usr/local/occlum/bin:/opt/occlum/toolchains/rust/bin:$PATH"
# TODO: Don't use "occlum-cargo"
occlum-cargo build -p occlume-enclave-node

# TODO: Remove
# 現状、コンテナ内でaesm serviceの起動が必要
# https://github.com/occlum/occlum/pull/443
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service

if [ -d occlum-instance ]; then
  echo "Remove existing a occlum-instance"
  rm -rf occlum-instance
fi

mkdir occlum-instance
cd "$ANONIFY_ROOT"/occlum-instance
occlum init

# Enlarge libos kernel space heap size to 64bytes
sed -i -e "s/\"kernel_space_heap_size\": \"32MB\"/\"kernel_space_heap_size\": \"64MB\"/" Occlum.json
cp ../target/x86_64-unknown-linux-musl/debug/occlume-enclave-node image/bin
occlum build
occlum run /bin/occlume-enclave-node
