#!/bin/bash

set -e

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

cd "$ANONIFY_ROOT"
occlum-cargo build -p occlume-enclave-node

if [ ! -d occlum-instance ]; then
  echo "Remove existing a occlum-instance"
  rm -rf occlum-instance
fi

mkdir occlum-instance && cd occlum-instance
occlum init
cp ../target/x86_64-unknown-linux-musl/debug/occlume-enclave-node image/bin
occlum build
occlum run /bin/occlume-enclave-node
