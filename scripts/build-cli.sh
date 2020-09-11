#!/bin/bash

set -e

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../example/erc20/cli"
echo $PWD
export SGX_MODE=HW

if [ -n "$1" ]; then
    if [ "$1" == "--release" ]; then
        echo "Build artifacts in release mode, with optimizations."
        cargo build --release
        exit
    fi
fi

echo "Build artifacts in debug mode."
RUST_BACKTRACE=1 cargo build
