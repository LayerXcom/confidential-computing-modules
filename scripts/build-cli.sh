#!/bin/bash

set -e

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../example/cli"
echo $PWD
export SGX_MODE=HW

# For docker
export ANONIFY_URL=http://172.28.1.1:8080

# For non-docker
# export ANONIFY_URL=http://172.18.0.3:8080

if [ -n "$1" ]; then
    if [ "$1" == "--release" ]; then
        echo "Build artifacts in release mode, with optimizations."
        cargo build --release
        exit
    fi
fi

echo "Build artifacts in debug mode."
RUST_BACKTRACE=1 cargo build
