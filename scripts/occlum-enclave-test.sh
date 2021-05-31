#!/bin/bash

set -ex

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

cd "$ANONIFY_ROOT"

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
cp Occlum.json Default-occlum.json

# Enlarge libos kernel space heap size to 128bytes.
# Set envinronment variables passed to the "root" LibOS processes.
jq '.resource_limits.kernel_space_heap_size|="128MB" |
  .env.default|=.+["SPID='$SPID'"] |
  .env.default|=.+["SUB_KEY='$SUB_KEY'"] |
  .env.default|=.+["IAS_URL='$IAS_URL'"] |
  .env.default|=.+["OCCLUM_ENCLAVE_IP_ADDRESS='$OCCLUM_ENCLAVE_IP_ADDRESS'"] |
  .env.default|=.+["OCCLUM_ENCLAVE_PORT='$OCCLUM_ENCLAVE_PORT'"]' \
  < Default-occlum.json \
  > Occlum.json

cp ../target/x86_64-unknown-linux-musl/debug/occlume-enclave-node image/bin
occlum build
occlum run /bin/occlume-enclave-node
